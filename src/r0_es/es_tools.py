# coding=UTF-8
import re
import time
from abc import ABC

import requests
import ujson
import traceback
import datetime
import dateutil.parser
import input_helper as ih

from http import HTTPStatus
from typing import Dict, Union

from requests.packages.urllib3.exceptions import InsecureRequestWarning

from oslo_log import log

from .http_base import HTTPClient
from .cfg_settings import ESConfig

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

LOG = log.getLogger(__name__)


def time_traits(raw_str: str):
    """
    从字符串中分别提取日期和时间

    Args:
        raw_str: 原生的字符串，匹配串
    Returns:
        datetime，可以直接进行大小比较
    """
    try:
        res_dt, res_index = dateutil.parser.parse(raw_str, fuzzy_with_tokens=True)
    except Exception as e:
        LOG.error(e)
        if "Unknown string format" in e.args[0]:
            date_re_str = "\d{4}[-/\.]*\d{1,2}[-/\.]*\d{1,2}"
            time_re_str = "\d{1,2}[:]\d{1,2}[:]?(?:\d{1,2})?"
            date_re = re.compile(date_re_str)
            time_re = re.compile(time_re_str)
            # dt_re = re.compile(f"{date_re_str}[.-/ T](?:{time_re_str})?")

            ans_date = date_re.findall(raw_str)
            ans_time = time_re.findall(raw_str)
            # ans_dt = dt_re.findall(raw_str)
            date_list = []
            if len(ans_date) > 0:
                date_list = [int(it) for it in ans_date[0].split(".")]
            if len(ans_time) > 0:
                time_list = [int(it) for it in ans_time[0].split(":")]
                date_list.extend(time_list)
            if len(date_list) > 0:
                res_dt = datetime.datetime(*date_list)
                LOG.info(f"Patch {e.args[1]} successfully.")
                return res_dt
            else:
                return None
        else:
            return None
    else:
        return res_dt


def query_generator(
        gte: int = None, lte: int = 0, time_unit: str = "d",
        page: int = None, size: int = 10, search_after: list = None,
        time_field: str = "@timestamp", include: str = None, exclude: str = None, filters: list = None
):
    """
    根据时间和页面大小生成查询query。

    如果指定了search_after, 或者只指定了size没有page，那么分页查询基于search after，
    核心是利用排序游标，在这里使用时间戳作为降序游标，以_id作为可选升序游标。

    如果指定了page和size，那么分页查询基于from-size。

    :param gte: 起始时间到现在的距离
    :param lte: 终止时间到现在的距离
    :param time_unit: 时间单位，默认为d(day)
    :param page: 页面序号
    :param size: 页面大小，但此选项在_delete_by_query会被忽略
    :param search_after: 上一次查询的最后一个游标
    :param time_field: 时间戳字段名称
    :param include: 输出时保留的字段
    :param exclude: 输出时忽略的字段
    :param filters: 过滤条件
    :return: 查询用的query
    """

    ans_query = {
        "size": size,
        "query": {
            "bool": {
                "filter": [
                    {
                        "range": {
                            time_field: {
                                "lte": f"now-{lte}{time_unit}",
                                "format": "epoch_millis"
                            }
                        }
                    },
                ],
            }
        },
        "_source": {

        }
    }
    if page and search_after:
        return {}
    if page is None:
        ans_query.update({
            "sort": [
                {
                    time_field: "desc",
                    "_id": "asc"
                }
            ]
        })
    if search_after is not None:
        ans_query.update({
            "search_after": search_after
        })
    if page is not None:
        ans_query.update({
            "from": page * size
        })
    if gte is not None:
        ans_query["query"]["bool"]["filter"][0]["range"][time_field].update({
            "gte": f"now-{gte}{time_unit}",
        })
    if include is not None and exclude is not None:
        raise Exception("Cannot specify both 'fields' and 'ignore_fields'")
    if include is not None:
        include = ih.get_list_from_arg_strings(include)
        ans_query["_source"].update({
            "include": include
        })
    if exclude is not None:
        exclude = ih.get_list_from_arg_strings(exclude)
        ans_query["_source"].update({
            "exclude": exclude
        })
    if filters is not None:
        ans_query["query"]["bool"]["filter"].extend(filters)
    return ans_query


class ESTools(HTTPClient, ABC):

    def __init__(
            self, conf_file=None, host: str = None, port: int = None,
            username: str = None, password: str = None, is_require_auth: bool = True,
            special_index: list = None,
    ):
        """
        初始化，并且建立HTTP连接

        :param conf_file: 配置文件的地址，配置文件必须是ini风格的
        :param host: es主机地址
        :param port: es端口，如果需要的话会以 host:port 的方式进行拼接
        :param username: 用户名
        :param password: 用户密码
        :param is_require_auth: 是否需要验证，这一步会在HTTPBase中进行验证
        :param special_index: 敏感索引、特殊索引，搜索时将会忽略
        """
        if conf_file:
            conf = ESConfig(conf_file)()
            super(ESTools, self).__init__(
                is_require_auth=conf.elasticsearch.is_require_auth,
                username=conf.elasticsearch.username,
                password=conf.elasticsearch.password,
            )
            self.conf = conf
            # if not conf.elasticsearch.username:
            #     raise ValueError("The username of an datasource for vehicle manager is required")
            # self = ESAPI(conf.elasticsearch.username, conf.elasticsearch.password)
            self.__username = conf.elasticsearch.username
            self.__password = conf.elasticsearch.password
            self.es_host = conf.elasticsearch.host
            self.special_index = conf.elasticsearch.special_index
        if host and username and password and is_require_auth:
            super(ESTools, self).__init__(
                is_require_auth=is_require_auth,
                username=username,
                password=password,
            )
            self.conf = {
                "host": host,
                "username": username,
                "password": password,
                "is_require_auth": is_require_auth,
            }
            self.__username = username
            self.__password = password
            self.es_host = host
            self.special_index = special_index
            if port:
                self.es_host = ":".join([self.es_host, str(port)])
                self.conf.update({"port": port})

    def get_json(self, url, **kwargs):
        rsp = self.get(url, **kwargs)
        if rsp:
            try:
                data = rsp.json()
                return data
            except Exception as e:
                LOG.error(f"error: {e}\n{traceback.print_exc()}")

    def get_doc_count(self, index_name: str):
        """
        获取某一index下doc的数量

        :param index_name: 索引名称
        :return:
        """
        url = f"{self.es_host}/_cat/count/{index_name}"
        rsp = self.get(url)
        if rsp and rsp.status_code == 200:
            count = int((rsp.text.split(" "))[-1].split("\n")[0])
            # count = rsp["count"]
            # elasticsearch.exceptions.UnsupportedProductError:
            # The client noticed that the server is not a supported distribution of Elasticsearch to 7.10.1
            return count
        else:
            return None

    def get_indices_info(self, index: str):
        """
        获取索引信息

        :param index: 索引名称
        :return:
        """
        url = f"{self.es_host}/{index}"
        rsp = self.get(url)
        if rsp and rsp.status_code == 200:
            return rsp.json()
        else:
            return None

    def exists_index(self, index: str):
        """
        判断index是否存在

        :param index: 索引名称
        :return: bool
        """
        rsp = self.get_indices_info(index)
        if rsp:
            return True
        else:
            return False
        # url = f"{self.es_host}/{index_name}"
        # rsp = self.head(url)
        # if rsp and rsp.status_code == HTTPStatus.OK:
        #     return True
        # elif rsp and rsp.status_code == HTTPStatus.NOT_FOUND:
        #     return False
        # else:
        #     return False

    def get_indices(self, is_filter_sys_index: bool = True) -> list:
        """
        获取所有索引列表

        :param is_filter_sys_index: 是否过滤系统索引，默认为True
        :return: 索引列表
        """

        url = f"{self.es_host}/_cat/indices"
        params = dict(h="index", s="index")
        rsp = self.get(url, params=params)
        if rsp and rsp.status_code == HTTPStatus.OK:
            data = rsp.text.strip().split('\n')
            if not is_filter_sys_index:
                return data
            filter_data = []
            for item in data:
                if re.match("^\.", item) and item not in self.special_index:
                    continue
                filter_data.append(item)
            return filter_data
        return []

    def create_index(self, index_prefix: str, index_mapping: Dict = None,
                     number_of_shards: int = 1, number_of_replicas: int = 1, auto_timestamp: bool = True):
        """
        创建一个新索引，并添加创建时间后缀，yyyy.MM.dd

        :param auto_timestamp: 是否补充时间戳到index尾部
        :param index_prefix: 索引
        :param index_mapping: 创建索引API允许提供的类型映射，可以为空
        :param number_of_shards: 碎片的数量
        :param number_of_replicas: 副本的数量
        :return: 如果成功，返回创建的索引名称；否则返回 None
        """
        pre_mapping = {
            "@timestamp": {
                "format": "strict_date_optional_time||epoch_millis",
                # Examples: yyyy-MM-dd'T'HH:mm:ss.SSSZ or yyyy-MM-dd.
                "type": "date",
                # "enabled": True
            }
        }
        if not index_mapping:
            index_mapping = {"properties": {}}
        index_mapping["properties"].update(pre_mapping)
        data = {
            "settings": {
                "index": {
                    "number_of_shards": number_of_shards,
                    "number_of_replicas": number_of_replicas
                }
            },
            "mappings": index_mapping
        }
        timestamp = str(datetime.datetime.utcnow().strftime("%Y.%m.%d"))
        index_name = index_prefix
        if auto_timestamp:
            index_name = "-".join([index_prefix, timestamp])

        if not self.exists_index(index_name):
            url = f"{self.es_host}/{index_name}"
            rsp = self.put(url, data=ujson.dumps(data))
            if rsp and rsp.status_code == HTTPStatus.OK:
                return index_name
            return None
        else:
            return None

    def delete_index(self, index: str) -> bool:
        """
        删除指定索引

        :param index: 索引名称
        :return: bool，删除成功返回True，否则返回False
        """
        url = f"{self.es_host}/{index}"
        rsp = self.delete(url)
        if rsp and rsp.status_code == HTTPStatus.OK:
            return True
        return False

    def delete_all_index(self, shards: list):
        """
        删除指定索引

        - 0824[update]: 删除操作过于危险，不允许空参数
        :param shards: 索引列表
        :return: None
        """
        # if shards is None:
        #     indices = self.get_indices()
        # else:
        #     indices = shards
        for index in shards:
            if self.delete_index(index):
                LOG.info(f"success delete {index}")
            else:
                LOG.info(f"failure delete {index}")

    def delete_index_by_date(self, index_name: str, date_str: str) -> int:
        """
        删除指定时间的索引

        :param index_name:
        :param date_str:
        :return: int，成功删除的索引数量。出错返回 -1
        """

        pattern_dt = time_traits(date_str)
        data = self.get_indices()
        cnt = 0
        for index in data:
            matching_mt = time_traits(index)
            if matching_mt:

                if index_name in index and matching_mt == pattern_dt:
                    if self.delete_index(index):
                        cnt += 1
                    else:
                        return -1
        return cnt

    def delete_index_by_time_frame(
            self, index_include: str,
            gte: int, lte: int = 0, time_unit: str = "days"
    ):
        """
        删除指定时间范围的索引

        :param index_include: 索引中需要包含的子字符串
        :param gte: 起始时间到现在的距离
        :param lte: 终止时间到现在的距离
        :param time_unit: 时间单位，默认为days, 由于需要匹配 datetime.timedelta 所以只接收 ["days", "seconds", "minutes", "hours", "weeks"]
        :return: 如果成功返回删除的数量, 否则返回对应的状态码
        """

        if time_unit not in ["days", "seconds", "minutes", "hours", "weeks"]:
            time_unit = "days"
        args_gte = {time_unit: -1 * gte}
        args_lte = {time_unit: -1 * lte}
        gte_dt = datetime.datetime.utcnow() + datetime.timedelta(**args_gte)
        lte_dt = datetime.datetime.utcnow() + datetime.timedelta(**args_lte)
        data = self.get_indices()
        cnt = 0
        for index in data:
            matching_mt = time_traits(index)
            if matching_mt:
                if index_include in index and gte_dt <= matching_mt <= lte_dt:
                    if self.delete_index(index):
                        cnt += 1
                    else:
                        return -1
        return cnt

    def upsert_doc(self, index_name: str, doc_id: Union[str, int] = None, doc_body: Dict = None) -> int:
        """
        新增/更新一条记录，并且更新 @timestamp 为新增/更新时间

        :param index_name: 准确的索引名称
        :param doc_id: 记录的id，不指定时插入会使用自增长id
        :param doc_body: 记录 body
        :return: 结果的状态码
        """

        if doc_body is None:
            doc_body = {}
        timestamp = str(datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
        doc_body.update({"@timestamp": timestamp})
        if self.exists_index(index_name):
            # rsp = None
            if doc_id is None:
                url = f"{self.es_host}/{index_name}/_doc/"
                rsp = self.post(url, data=ujson.dumps(doc_body))
            else:
                url = f"{self.es_host}/{index_name}/_doc/{doc_id}"
                rsp = self.put(url, data=ujson.dumps(doc_body))

            rsp_json = ujson.loads(rsp.text)
            if rsp_json.get("result"):
                if rsp_json["result"] == "created":
                    return HTTPStatus.CREATED
                elif rsp_json["result"] == "updated":
                    return HTTPStatus.OK
            return HTTPStatus.BAD_REQUEST
        else:
            # print(f"{index_name} not found.")
            return HTTPStatus.NOT_FOUND

    def delete_doc_by_time_frame(
            self, index_name: str,
            gte: int = None, lte: int = 0, time_unit: str = "d",
            time_field: str = "@timestamp"
    ):
        """
        根据提供的时间范围删除记录

        :param index_name: 索引名称
        :param gte: 起始时间到现在的距离
        :param lte: 终止时间到现在的距离
        :param time_unit: 时间单位，默认为d(day)
        参考 https://www.elastic.co/guide/en/elasticsearch/reference/current/common-options.html#date-math
        :param time_field: 搜索所使用的标识时间的字段
        :return: 删除的数量, 如果出错，则返回-1
        """
        ans_query = query_generator(gte, lte, time_unit, time_field=time_field)
        if self.exists_index(index_name):
            url = f"{self.es_host}/{index_name}/_delete_by_query"
            rsp = self.post(url, data=ujson.dumps(ans_query))
            if rsp and rsp.status_code == HTTPStatus.OK:
                dict_res = ujson.loads(rsp.text)
                return dict_res["deleted"]
            else:
                return -1
        else:
            return -1

    def query_doc(
            self, index_name: str, page: int = None, size: int = None,
            include: str = None, exclude: str = None,
            gte: int = None, lte: int = 0, time_unit: str = "d",
            time_field: str = "@timestamp", filters: Dict = None
    ):
        """
        按页查询，from-size法

        :param index_name: 索引名称
        :param page: 页面下标
        :param size: 页面大小
        :param include: 输出时保留的字段
        :param exclude: 输出时忽略的字段
        :param gte: 起始时间到现在的距离
        :param lte: 终止时间到现在的距离
        :param time_unit: 时间单位，默认为d(day)
        - 参考 https://www.elastic.co/guide/en/elasticsearch/reference/current/common-options.html#date-math
        :param time_field: 时间戳字段名称
        :param filters: 过滤条件
        :return: 返回包含结果的列表
        """
        if not page and not size:
            page, size = 0, self.get_doc_count(index_name=index_name)
        if page * size + size > 9999:
            page, size = 0, 9999

        if self.exists_index(index_name):
            ans_query = query_generator(
                gte, lte, time_unit, page=page, size=size, time_field=time_field,
                include=include, exclude=exclude, filters=filters
            )

            url = f"{self.es_host}/{index_name}/_search"
            rsp = self.post(url, data=ujson.dumps(ans_query))
            if rsp and rsp.status_code == HTTPStatus.OK:
                return ujson.loads(rsp.text)["hits"]["hits"]
            else:
                return None
        else:
            return None
        pass

    def query_doc_tp(
            self, index_name: str, size: int = 100,
            include: str = None, exclude: str = None,
            gte: int = None, lte: int = 0, time_unit: str = "d",
            time_field: str = "@timestamp", filters: Dict = None
    ):
        """
        以线程池的方式获取doc

        :param index_name: 索引名称
        :param size: 每个线程查询的size
        :param include: 输出时保留的字段
        :param exclude: 输出时忽略的字段
        :param gte: 起始时间到现在的距离
        :param lte: 终止时间到现在的距离
        :param time_unit: 时间单位，默认为d(day)
        - 参考 https://www.elastic.co/guide/en/elasticsearch/reference/current/common-options.html#date-math
        :param time_field: 时间戳字段名称
        :param filters: 过滤条件
        :return: 返回包含结果的列表
        """
        from concurrent.futures import ThreadPoolExecutor, FIRST_COMPLETED, wait, as_completed
        with ThreadPoolExecutor() as tp:
            total = self.get_doc_count(index_name=index_name)
            pages = (total // size) + 1
            if total > 9999:
                pages, size = 1, 9999
            tasks = [
                tp.submit(
                    self.query_doc,
                    index_name, it, size, include, exclude, gte, lte, time_unit, time_field, filters
                )
                for it in range(pages)
            ]
            wait(tasks, return_when=FIRST_COMPLETED)
            ans = []
            for future in as_completed(tasks):
                data = future.result()
                if data:
                    ans.extend(data)
            return ans

    def query_doc_huge(
            self, index_name: str,
            include: str = None, exclude: str = None,
            gte: int = None, lte: int = 0, time_unit: str = "d",
            time_field: str = "@timestamp", filters: Dict = None
    ):
        """
        基于search-after，查询10000条以上的数据，但无法分页

        :param index_name:索引名称
        :param include: 输出时保留的字段
        :param exclude: 输出时忽略的字段
        :param gte: 起始时间到现在的距离
        :param lte: 终止时间到现在的距离
        :param time_unit: 时间单位，默认为d(day)
        - 参考 https://www.elastic.co/guide/en/elasticsearch/reference/current/common-options.html#date-math
        :param time_field:搜索所使用的标识时间的字段
        :param filters: 过滤条件
        :return: 返回包含结果的列表
        """

        size = 10000
        ans_query = query_generator(
            gte, lte, time_unit, size=size, time_field=time_field, include=include,
            exclude=exclude, filters=filters
        )
        ans_cnt = 0
        if self.exists_index(index_name):
            url = f"{self.es_host}/{index_name}/_search"
            rsp = self.post(url, data=ujson.dumps(ans_query))
            if rsp and rsp.status_code == HTTPStatus.OK:
                dict_res = ujson.loads(rsp.text)
                ans_cnt += size
                # total = dict_res["hits"]["total"]["value"]
                total = self.get_doc_count(index_name=index_name)
                sub_dict_res = dict_res
                while ans_cnt < total:
                    sub_search_after = sub_dict_res["hits"]["hits"][size - 1]["sort"]
                    sub_ans_query = query_generator(
                        gte, lte, time_unit,
                        size=size,
                        search_after=sub_search_after,
                        time_field=time_field
                    )
                    sub_rsp = self.post(url, data=ujson.dumps(sub_ans_query))
                    sub_dict_res = ujson.loads(sub_rsp.text)
                    ans_cnt += size
                    dict_res["hits"]["hits"].extend(sub_dict_res["hits"]["hits"])
                return dict_res["hits"]["hits"]
            else:
                return rsp and rsp.status_code
        else:
            LOG.error(f"{index_name} does not exists")
            return None

    def query_doc_custom(
            self,
            index_name: str,
            query: dict,
            page: int = 0,
            size: int = 10
    ):
        if page is not None and size != 0:
            query["from"] = page * size
            query["size"] = size
        if self.exists_index(index_name):
            url = f"{self.es_host}/{index_name}/_search"
            rsp = self.post(url, data=ujson.dumps(query))
            if rsp and rsp.status_code == HTTPStatus.OK:
                dict_res = rsp.json()
                return dict_res

    def get_repositories(self) -> list:
        """
        获取仓库列表

        :return: 返回仓库列表，
                 例如： [
                 {"id": "backup_all", "type": "fs"},
                 ]
        """
        repo_res = []
        url = f"{self.es_host}/_cat/repositories?v"
        rsp = self.get(url)
        if rsp and rsp.status_code == HTTPStatus.OK:
            data = rsp.text.strip().split('\n')
            col = []
            for i, item in enumerate(data):
                if i == 0:
                    col = item.strip().split()
                    continue
                lds = item.strip().split()
                tmp = dict()
                for c in range(len(col)):
                    tmp[col[c]] = lds[c]
                repo_res.append(tmp)
        return repo_res

    def create_snapshot_repositories(self, repo_name: str) -> bool:
        """
        创建快照仓库

        :param repo_name: 仓库名称
        :return: bool，创建成功返回True，否则返回False
        """
        # PUT /_snapshot/my_repository
        # {
        #   "type": "fs",
        #   "settings": {
        #     "location": "my_backup_location"
        #   }
        # }

        url = f"{self.es_host}/_snapshot/{repo_name}"
        data = {
            "type": "fs",
            "settings": {
                "location": repo_name,
                "compress": True
            }
        }
        rsp = self.put(url, data=ujson.dumps(data))
        if rsp and rsp.status_code == HTTPStatus.OK:
            return True
        return False

    def get_snapshot_repositories(self, repo_name: str) -> dict or None:
        """
        获取快照仓库信息

        :param repo_name: 仓库名称
        :return: dict，仓库信息
                 例如：
                 {
                  "backup_all" : {
                    "type" : "fs",
                    "settings" : {
                      "readonly" : "true",
                      "compress" : "true",
                      "location" : "backup_all"
                    }
                  }
                }
        """
        # GET /_snapshot/my_repository
        url = f"{self.es_host}/_snapshot/{repo_name}"
        rsp = self.get(url)
        if rsp and rsp.status_code == HTTPStatus.OK:
            return rsp.json()

    def delete_snapshot_repositories(self, repo_name: str) -> bool:
        """
        删除快照仓库

        :param repo_name: 仓库名称
        :return: bool，删除成功返回True，否则返回False
        """
        # DELETE /_snapshot/my_repository
        url = f"{self.es_host}/_snapshot/{repo_name}"
        rsp = self.delete(url)
        if rsp and rsp.status_code == HTTPStatus.OK:
            return True
        return False

    def cleanup_snapshot_repositories(self, repo_name: str) -> dict or None:
        """
        清理快照仓库

        :param repo_name: 仓库名称
        :return: dict
        """
        # POST /_snapshot/my_repository/_cleanup
        url = f"{self.es_host}/_snapshot/{repo_name}/_cleanup"
        rsp = self.post(url)
        if rsp and rsp.status_code == HTTPStatus.OK:
            return rsp.json()

    def create_snapshot(
            self, repo_name: str, snapshot_name: str, indices: list = None,
            wait_for_completion: bool = True
    ) -> dict or None:  # noqat: E501
        """
        创建快照

        :param repo_name: 仓库名称
        :param snapshot_name: 快照名称
        :param indices: 索引列表
        :param wait_for_completion: 是否等待创建完成
        :return: dict，例如：
                        {
                          "snapshot": {
                            "snapshot": "snapshot_2",
                            "uuid": "vdRctLCxSketdKb54xw67g",
                            "version_id": <version_id>,
                            "version": <version>,
                            "indices": [],
                            "data_streams": [],
                            "feature_states": [],
                            "include_global_state": false,
                            "metadata": {
                              "taken_by": "user123",
                              "taken_because": "backup before upgrading"
                            },
                            "state": "SUCCESS",
                            "start_time": "2020-06-25T14:00:28.850Z",
                            "start_time_in_millis": 1593093628850,
                            "end_time": "2020-06-25T14:00:28.850Z",
                            "end_time_in_millis": 1593094752018,
                            "duration_in_millis": 0,
                            "failures": [],
                            "shards": {
                              "total": 0,
                              "failed": 0,
                              "successful": 0
                            }
                          }
                        }
        """
        # PUT /_snapshot/my_repository/snapshot_2?wait_for_completion=true
        # {
        #   "indices": "index_1,index_2",
        #   "ignore_unavailable": true,
        #   "include_global_state": false,
        #   "metadata": {
        #     "taken_by": "user123",
        #     "taken_because": "backup before upgrading"
        #   }
        # }
        url = f"{self.es_host}/_snapshot/{repo_name}/{snapshot_name}"
        params = dict(
            wait_for_completion=wait_for_completion
        )
        data = {
            "indices": indices or ["*"],
            "ignore_unavailable": True,
            "include_global_state": False,
            "metadata": {
                "taken_by": "cfp",
                "taken_because": "backup before upgrading"
            }
        }
        rsp = self.put(url, params=params, data=ujson.dumps(data))
        if rsp and rsp.status_code == HTTPStatus.OK:
            return rsp.json()

    def get_snapshot(self, repo_name: str, snapshot_name: str) -> dict or None:  # noqat: E501
        """
        获取快照

        :param repo_name: 仓库名称
        :param snapshot_name: 快照名称
        :return: dict，例如：
                    {
                      "snapshots": [
                        {
                          "snapshot": "snapshot_2",
                          "uuid": "vdRctLCxSketdKb54xw67g",
                          "version_id": <version_id>,
                          "version": <version>,
                          "indices": [],
                          "data_streams": [],
                          "feature_states": [],
                          "include_global_state": true,
                          "state": "SUCCESS",
                          "start_time": "2020-07-06T21:55:18.129Z",
                          "start_time_in_millis": 1593093628850,
                          "end_time": "2020-07-06T21:55:18.876Z",
                          "end_time_in_millis": 1593094752018,
                          "duration_in_millis": 0,
                          "failures": [],
                          "shards": {
                            "total": 0,
                            "failed": 0,
                            "successful": 0
                          }
                        }
                      ]
                    }
        """
        # GET /_snapshot/my_repository/my_snapshot
        url = f"{self.es_host}/_snapshot/{repo_name}/{snapshot_name}"
        rsp = self.get(url)
        if rsp and rsp.status_code == HTTPStatus.OK:
            return rsp.json()

    def get_snapshot_status(self, repo_name: str, snapshot_name: str) -> dict or None:  # noqat: E501
        """
        获取快照状态

        :param repo_name: 仓库名称
        :param snapshot_name: 快照名称
        :return: dict
        """
        # GET /_snapshot/my_repository/my_snapshot/_status
        url = f"{self.es_host}/_snapshot/{repo_name}/{snapshot_name}/_status"
        rsp = self.get(url)
        if rsp and rsp.status_code == HTTPStatus.OK:
            return rsp.json()

    def restore_snapshot(self, repo_name: str, snapshot_name: str, indices: str) -> dict or None:  # noqat: E501
        """
        恢复快照

        :param repo_name: 仓库名称
        :param snapshot_name: 快照名称
        :return: dict
        """
        # POST /_snapshot/backup/snapshot-2021-07-30-15-59/_restore?pretty&wait_for_completion=true
        # {
        #   "indices": "*",
        #   "ignore_unavailable": true,
        #   "include_global_state": false,
        #   "include_aliases": false,
        #   "index_settings": {
        #     "index.number_of_replicas": 1
        #   }
        # }
        url = f"{self.es_host}/_snapshot/{repo_name}/{snapshot_name}/_restore?pretty&wait_for_completion=true"
        data = {
            "indices": indices,
            "ignore_unavailable": True,
            "include_global_state": False,
            "include_aliases": False,
            "index_settings": {
                "index.number_of_replicas": 1
            }
        }
        rsp = self.post(url, data=ujson.dumps(data))
        if rsp and rsp.status_code == HTTPStatus.OK:
            return rsp.json()

    def restore_all_snapshot(self, repo_name: str, snapshot_name: str, shards: list = None):
        """
        恢复所有快照

        :param repo_name: 快照仓库
        :param snapshot_name:
        :param shards:
        :return:
        """
        if shards is None:
            sinfo = self.get_snapshot(repo_name, snapshot_name)
            indices = sinfo.get('snapshots')[-1].get("indices")
        else:
            indices = shards

        filter_indices = indices.copy()
        for index in indices:
            if re.match("^\.", index):
                filter_indices.remove(index)
        indices = filter_indices
        failure_list = []
        success_list = []
        t1 = time.time()
        count = 0
        threshold = 10
        while True and indices:
            try:
                for index in indices:
                    t1_1 = time.time()
                    data = self.restore_snapshot(repo_name, snapshot_name, index)
                    t1_2 = time.time()
                    with open('record.txt', 'a') as f:
                        f.write("indices: %-80s use time: %.6fs\n" % (index, t1_2 - t1_1))
                    if data:
                        if data.get('snapshot', {}).get('shards', {}).get('failed', 0) > 0:
                            print(
                                f"failure restore {repo_name}/{snapshot_name}, "
                                f"indices: {index}, use time: {t1_2 - t1_1}s"
                            )
                            failure_list.append({"index": index, "time": t1_2 - t1_1})
                        else:
                            success_list.append({"index": index, "time": t1_2 - t1_1})
                            print(
                                f"success restore {repo_name}/{snapshot_name}, "
                                f"indices: {index}, use time: {t1_2 - t1_1}s"
                            )
                    else:
                        print(
                            f"failure restore {repo_name}/{snapshot_name}, indices: {index}, use time: {t1_2 - t1_1}s")
                        failure_list.append({"index": index, "time": t1_2 - t1_1})
                    count += 1

                    t2 = time.time()
                    if count >= threshold:
                        with open('restore_success.txt', 'a') as f:
                            f.write(f"{repo_name}/{snapshot_name}\n")
                            f.write(f"date: {datetime.datetime.now()}\n")
                            f.write(f"use time: {t2 - t1}s\n")
                            for i in success_list:
                                f.write(f"{i}\n")
                            f.write("\n\n")

                        with open('restore_failure.txt', 'a') as f:
                            f.write(f"{repo_name}/{snapshot_name}\n")
                            f.write(f"date: {datetime.datetime.now()}\n")
                            f.write(f"use time: {t2 - t1}s\n")
                            for i in failure_list:
                                f.write(f"{i}\n")
                            f.write("\n\n")
                        threshold += 10
                        success_list.clear()
                        failure_list.clear()
                    if count >= len(indices):
                        break
            except Exception as e:
                print(e)

    def get_snapshot_shards(self, repo_name: str, snapshot_name: str):
        # GET /_snapshot/backup/snapshot-2021-07-30-15-59
        url = f"{self.es_host}/_snapshot/{repo_name}/{snapshot_name}"
        rsp = self.get(url)
        if rsp and rsp.status_code == HTTPStatus.OK:
            return rsp.json().get('snapshots')[0].get('indices')

    def get_shards_info(self):
        # GET /_cat/shards?h=index,shard,prirep,state,unassigned.reason&s=state
        url = f"{self.es_host}/_cat/shards?h=index,prirep,state&s=state"
        rsp = self.get(url)
        if rsp and rsp.status_code == HTTPStatus.OK:
            return (item.strip().split() for item in rsp.text.strip().split('\n'))

    def get_shards_pos(self):
        # GET /_cat/shards?h=index,state,ip,node&s=state
        url = f"{self.es_host}/_cat/shards?h=index,shard,state,ip,node&s=index"
        rsp = self.get(url)
        if rsp and rsp.status_code == HTTPStatus.OK:
            return (item.strip().split() for item in rsp.text.strip().split('\n'))

    def get_unassigned_shards(self):
        shards = self.get_shards_info()
        unassigned_res = []
        started_res = []
        if shards:
            for sarr in shards:
                if sarr[1] == 'p' and sarr[2] == 'UNASSIGNED':
                    unassigned_res.append(sarr[0])
                if sarr[1] == 'p' and sarr[2] == 'STARTED':
                    started_res.append(sarr[0])
        return started_res, unassigned_res

    def delete_unassigned_index_and_restore(self, repo_name: str, snapshot_name: str):
        started_res, unassigned_shards = self.get_unassigned_shards()
        self.delete_all_index(unassigned_shards)
        indices = self.get_snapshot_shards(repo_name, snapshot_name)
        unassigned_shards = list(set(indices) - set(started_res))
        self.restore_all_snapshot(repo_name, snapshot_name, unassigned_shards)

    def vail_shards_rack(self):
        shards_pos = self.get_shards_pos()

        if shards_pos:
            shards_dict = dict()
            for s in shards_pos:
                s_index = s[0]
                s_shard = s[1]
                # s_state = s[2]
                s_ip = s[3]
                # s_node = s[4]
                key = f"{s_index}_{s_shard}"
                if key in shards_dict:
                    shards_dict[key].append(s_ip)
                else:
                    shards_dict[key] = [s_ip]
            failure_res = []
            success_count = 0
            failure_count = 0
            for index, ips in shards_dict.items():
                if len(ips) != len(set(ips)):
                    failure_res.append(index)
                    failure_count += 1
                else:
                    success_count += 1

            return dict(success_count=success_count, failure_count=failure_count, failure_res=failure_res)

    def vail_index_count(self):
        # GET /_cat/indices?v&h=index,docs.count
        url = f"{self.es_host}/_cat/indices?h=index,docs.count&s=index"
        rsp = self.get(url)
        new_data = dict()
        if rsp and rsp.status_code == HTTPStatus.OK:
            data = (item.strip().split() for item in rsp.text.strip().split('\n'))
            for d in data:
                index = d[0]
                count = d[1]
                if index in new_data:
                    new_data[index] += count
                else:
                    new_data[index] = count
        else:
            raise

        url = f"{self.es_host}/_cat/indices?h=index,docs.count&s=index"
        rsp = self.get(url)
        old_data = dict()
        if rsp and rsp.status_code == HTTPStatus.OK:
            data = (item.strip().split() for item in rsp.text.strip().split('\n'))
            for d in data:
                if len(d) != 2:
                    continue
                index = d[0]
                count = d[1]
                if index in old_data:
                    old_data[index] += count
                else:
                    old_data[index] = count
        else:
            raise

        success_res = []
        failure_res = []
        other_res = []
        for key, val in new_data.items():
            # if re.match("^\.", key) and key not in self.special_index:
            #     continue
            if not old_data.get(key):
                other_res.append(key)
                continue
            if old_data.get(key, 0) == val:
                success_res.append(key)
            if old_data.get(key, 0) != val:
                failure_res.append(key)
        return dict(
            success_count=len(success_res),
            success_res=success_res,
            failure_count=len(failure_res),
            failure_res=failure_res,
            other_count=len(other_res),
            other_res=other_res
        )

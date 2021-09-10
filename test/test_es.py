import os
import time
import pytest

from timeit import default_timer as timer
from functools import wraps

from src.r0_es.es_tools import ESTools


def fun_run_time(func):
    @wraps(func)
    def inner(*args, **kwargs):
        tic = timer()
        ret = func(*args, **kwargs)
        toc = timer()
        print("{} cost {} s".format(func.__name__, toc - tic))
        return ret

    return inner


es_client = ESTools(os.path.abspath(os.path.join(os.path.dirname(__file__), "prod.cfg")))


@pytest.mark.skipif(not es_client, reason="Not connected to es")
class TestEs(object):
    @fun_run_time
    def test_get_doc_count(self):
        res = es_client.get_doc_count("sentry-1*")
        assert (res is not None)

    @fun_run_time
    def test_get_indices_info(self):
        res = es_client.get_indices_info("sentry-*")
        assert (res is not None)

    @fun_run_time
    def test_exists_index(self):
        res = es_client.exists_index("sentry-*")
        assert (res is not False)

    @fun_run_time
    def test_get_indices(self):
        res = es_client.get_indices()
        assert (res != [])

    @fun_run_time
    def test_create_delete_index(self):
        res = es_client.create_index("test-qwq")
        es_client.delete_index(res)
        assert (not es_client.exists_index(res))

    @fun_run_time
    def test_delete_index_by_date(self):
        res_index = es_client.create_index("test-qwq")
        res_cnt = es_client.delete_index_by_date(res_index, "09-10")
        assert (res_cnt == 1 and not es_client.exists_index(res_index))

    @fun_run_time
    def test_delete_index_by_time_frame(self):
        res_index = es_client.create_index("test-qwq")
        res_cnt = es_client.delete_index_by_time_frame(res_index, gte=1)
        assert (res_cnt == 1 and not es_client.exists_index(res_index))

    @fun_run_time
    def test_upsert_doc(self):
        res_index = es_client.create_index("test-qwq")
        res_status = es_client.upsert_doc(index_name=res_index, doc_body={
            "name": "qwq"
        })
        res_cnt = es_client.delete_index_by_date(res_index, "09-10")
        assert (res_status == 201 and res_cnt == 1 and not es_client.exists_index(res_index))

    @fun_run_time
    def test_delete_doc_by_time_frame(self):
        res_index = es_client.create_index("test-qwq")
        res_status = es_client.upsert_doc(index_name=res_index, doc_body={
            "name": "qwq"
        })
        time.sleep(2)
        res_del = es_client.delete_doc_by_time_frame(res_index)
        res_cnt = es_client.delete_index_by_date(res_index, "09-10")
        assert (res_cnt == 1 and not es_client.exists_index(res_index))
        assert (res_del == 1)

    @fun_run_time
    def test_query_doc(self):
        res_index = es_client.create_index("test-qwq")
        for it in range(101):
            es_client.upsert_doc(index_name=res_index, doc_body={
                "name": "qwq",
                "index": 1
            })
        time.sleep(2)
        res_doc = es_client.query_doc(res_index)
        res_cnt = es_client.delete_index_by_date(res_index, "09-10")
        assert (res_cnt == 1 and not es_client.exists_index(res_index))
        assert (len(res_doc) == 101)

    @fun_run_time
    def test_query_doc_tp(self):
        res_index = es_client.create_index("test-qwq")
        for it in range(101):
            es_client.upsert_doc(index_name=res_index, doc_body={
                "name": "qwq",
                "index": 1
            })
        time.sleep(2)
        res_doc = es_client.query_doc_tp(res_index)
        res_cnt = es_client.delete_index_by_date(res_index, "09-10")
        assert (res_cnt == 1 and not es_client.exists_index(res_index))
        assert (len(res_doc) == 101)


if __name__ == "__main__":
    pytest.main(["-s"])

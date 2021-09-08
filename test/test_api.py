import time

from src.r0_es import ESTools
from timeit import default_timer as timer
from functools import wraps


def fun_run_time(func):
    @wraps(func)
    def inner(*args, **kwargs):
        tic = timer()
        ret = func(*args, **kwargs)
        toc = timer()
        print("{} cost {} s".format(func.__name__, toc - tic))
        return ret

    return inner


def main():
    # print(prod_cfg.elasticsearch.username)
    # es_client = ESClient(
    #     host="https://prod-elasticsearch.deeproute.cn",
    #     username="elastic", password="!QAZ@WSX", is_require_auth=True
    # )
    import os
    es_client = ESTools(
        os.path.abspath(os.path.join(os.path.dirname(__file__), "prod.cfg"))
    )
    # res = es_client.get_indices()
    # print(res)
    res = es_client.get_doc_count("sentry-*")
    print(res)
    # res = es_client.get_indices_info("sentry-*")
    # print(res)
    res = es_client.create_index("test-qwq")
    print(res)
    # res = es_client.delete_index("test-qwq-2021.09.02")
    # print(res)
    # res = es_client.delete_index_by_date("test-qwq", date_str="09-02")
    # print(res)
    for it in range(5):
        es_client.upsert_doc("test-qwq-2021.09.08", doc_body={
            "name": "qwq",
            "index": it
        })
    res = es_client.upsert_doc("test-qwq-2021.09.08", doc_body={
        "name": "qwq",
        "index": 1
    })
    print(res)
    time.sleep(2)
    res = es_client.get_doc_count("test-qwq-2021.09.08")
    print(res)
    time.sleep(2)
    res = es_client.query_doc("test-qwq-2021.09.08", page=0, size=100)
    print(len(res))
    print(res)

    tic = timer()
    res = es_client.query_doc("test-qwq-2021.09.08")
    print(len(res))
    toc = timer()
    print(toc - tic)

    tic = timer()
    res = es_client.query_doc_tp("test-qwq-2021.09.08")
    print(len(res))
    toc = timer()
    print(toc - tic)

    tic = timer()
    res = es_client.query_doc_huge("test-qwq-2021.09.08")
    print(len(res))
    toc = timer()
    print(toc - tic)

    res = es_client.delete_index("test-qwq-2021.09.08")
    print(res)
    res = es_client.delete_index("test-qwq-2021.09.08-2021.09.08")
    print(res)

    # tic = timer()
    # res = es_client.delete_doc_by_time_frame("test-qwq-2021.09.02")
    # print(res)
    # toc = timer()
    # print(toc - tic)


if __name__ == '__main__':
    main()

# R0 es tools
[![License](https://img.shields.io/badge/for-elasticSearch-brightgreen)]()
[![Language](https://img.shields.io/pypi/pyversions/fastapi)]()
[![Autor](https://img.shields.io/badge/Autor-r0-pink)]()

一个连接elasticSearch的工具，帮助用户添加、删除、修改和检查文档、索引和管理快照。

有着更容易使用的日期相关的操作和管理快照存储库的功能。

此外，该项目还配置了一个小插件来监视文件和自动生成文档。

A tool to connect elasticSearch，
and help users to add, delete, modify, and check documents and indexe.

Date-related operations are easier to use and manage snapshot repositories.

In addition, this project also configured a small plug-in to monitor files and automatically monitor documents.

## Get it
```shell
pip3 install git+git://github.com/boogieLing/r0_es
pip3 install git+https://github.com/boogieLing/r0_es.git
```
## USEAGE
### initialize
你有两种方式去初始化，一种是指定一个ini风格的配置文件，一种是手动传入所需的参数。

You can do this either by specifying an INI style configuration file or by manually passing in the required parameters.

```python
import os
es_client = ESTools(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "prod.cfg"))
)

# es_client = ESTools(
#     host="https://127.0.0.1",
#     username="elastic", password="123456", is_require_auth=True
# )
```
注意，不管是使用何种方式，如果您指定了用户名和密码，那么您最好指定"is_require_auth"为True。

Note that either way, if you specify a username and password, it is best to specify "is_require_auth" as True.

### Time dependent operations
**增加索引** Create index

```python
res = es_client.create_index("test-qwq")
res = es_client.create_index("test-qwq", auto_timestamp=False)
```
前者会生成索引"test-qwq-2021.09.01"，而后者只会生成"test-qwq"，这取决与您是否需要这项功能。

因为通常在使用ES索引的时候我们都会利用时间戳进行分片。

The former generates the index "test-qwq-2021.09.01", while the latter only generates "test-qwq", depending on whether you need this feature. 

Because usually when we use ES indexes we're going to use timestamps for sharding.

----
**删除和查询索引** Delete and query indexes

您可以直接查询所有索引列表

You can query all index lists directly
```python
res = es_client.get_indices()
```
当然，常用的应该是删除某一天或者某一时间范围的索引。

Of course, it is common to drop indexes for a certain day or time range.
```python
res_cnt = es_client.delete_index_by_date("test-*", "09-01")
res_cnt = es_client.delete_index_by_time_frame("*", gte=1)
```
前者会删除09月01日所有以"test-"开头的索引，而后者则会删除前一天至今天的所有索引

The former will delete all indexes starting with "test-" on September 01, while the latter will delete all indexes from the previous day to today.

----
**查询文档** Query the document

对于查询文档，有更丰富的查询姿势，
您可以选择分页查询，巨量查询，分页的同时按时间范围查询，查询全部的同时按时间范围查询，查询全部的同时使用多线程查询。

For query documents, there are more rich query posture, 
you can choose paging query, huge query, paging at the same time according to the time range query, 
query all at the same time according to the time range query, query all at the same time using multi-thread query.

----
## Automatic document
在本项目还有一个可执行文件"docs_watcher"，您可以参考我的另一个项目来使用他。

https://github.com/boogieLing/r0_doc_watcher

本项目的接口文档就是由这个小插件生成的，所有功能的详细的使用方法可以在html文档中看到。

There is also an executable file "Docs Watcher" in this project, which you can use by referring to another of my projects.

The interface documentation for this project is generated by this small plug-in, and detailed usage of all functions can be seen in the HTML document.

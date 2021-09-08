# -*- coding: utf-8 -*-
# @Time: 2021/9/3
# @Author: cfp
import threading
from http import HTTPStatus

import requests
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from oslo_log import log

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
LOG = log.getLogger(__name__)


class AuthMode:
    BASE_AUTH = 'base_auth'
    HEAD_AUTH = 'head_auth'


class HTTPClient(requests.Session):
    def __init__(self, is_require_auth=False, auth_mode=AuthMode.BASE_AUTH, username: str = None, password: str = None):
        super(HTTPClient, self).__init__()
        self.is_require_auth = is_require_auth
        self.auth_mode = auth_mode
        self._check_auth_params(username, password)
        self.headers.update({"Content-Type": "application/json"})
        self.verify = False
        self._lock = threading.Lock()
        self.__auth_head = None

    def _check_auth_params(self, username, password):
        if self.is_require_auth:
            if not (username and password):
                raise ValueError("[HTTPClient] username and password must provider")
            if self.auth_mode == AuthMode.BASE_AUTH:
                self.auth = HTTPBasicAuth(username, password)

    def _update_authorization(self, auth_head):
        self.headers.update(auth_head)

    def clear_auth_head(self):
        self.__auth_head = None

    def _auth(self):
        if self.is_require_auth:
            self.do_auth()

    def set_auth_head(self, auth_head):
        self.__auth_head = auth_head

    def do_auth(self):
        raise NotImplementedError

    def update_token(self):
        if not self.is_require_auth and self.auth_mode != AuthMode.HEAD_AUTH:
            return
        if self.__auth_head:
            self._update_authorization(self.__auth_head)
        with self._lock:
            if not self.__auth_head:
                self._auth()
            self._update_authorization(self.__auth_head)

    def get(self, url, **kwargs):
        rsp = super(HTTPClient, self).get(url, **kwargs)
        if rsp.status_code == HTTPStatus.OK:
            return rsp
        else:
            self.clear_auth_head()
            LOG.error(f"[HTTPClient] GET {url} failure, status_code: {rsp.status_code}, msg: {rsp.text}")

    def post(self, url, data=None, **kwargs):
        rsp = super(HTTPClient, self).post(url=url, data=data, **kwargs)
        if rsp.status_code == HTTPStatus.OK or rsp.status_code == HTTPStatus.CREATED:
            return rsp
        else:
            self.clear_auth_head()
            LOG.error(f"[HTTPClient] post {url} failure, data: {data}, status_code: {rsp.status_code}, msg: {rsp.text}")

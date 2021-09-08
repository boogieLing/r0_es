import threading

from oslo_config import cfg


def register_es(cur_config):
    group = cfg.OptGroup(
        name="elasticsearch",
        title="elasticsearch config"
    )
    opts = [
        cfg.StrOpt("host"),
        cfg.PortOpt("port"),
        cfg.StrOpt("username"),
        cfg.StrOpt("password"),
        cfg.ListOpt("special_index"),
        cfg.BoolOpt("is_require_auth")
    ]
    cur_config.register_opts(opts, group=group)


class SingleESConfig(object):
    """
    单例模式的Config

    Config for singleton mode
    """
    _instance_lock = threading.Lock()
    _cfg = None

    def __init__(self, path: str = None):
        self._cfg = cfg.ConfigOpts()
        register_es(self._cfg)
        self._cfg([], validate_default_values=True, default_config_files=[path])

    def __new__(cls, *args, **kwargs):
        if not hasattr(SingleESConfig, "_instance"):
            with SingleESConfig._instance_lock:
                if not hasattr(SingleESConfig, "_instance"):
                    SingleESConfig._instance = object.__new__(cls)
        return SingleESConfig._instance

    def __call__(self, *args, **kwargs):
        return self._cfg


class ESConfig(object):
    """
    普通Config

    Ordinary Config
    """
    def __init__(self, path: str = None):
        self._cfg = cfg.ConfigOpts()
        register_es(self._cfg)
        self._cfg([], validate_default_values=True, default_config_files=[path])

    def __call__(self, *args, **kwargs):
        return self._cfg


def set_es_config(conf_file):
    global _single_cfg
    _single_cfg = SingleESConfig(conf_file)()


def get_es_config():
    return _single_cfg


_single_cfg = None

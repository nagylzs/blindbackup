from ..syncdir import FsProvider
from .localfs import LocalFsProvider
from .blindfs import BlindFsProvider

__PROVIDER_CLASSES = {}


def register_provider_class(provider_class):
    """Register filesystem provider class."""
    global __PROVIDER_CLASSES
    assert issubclass(provider_class, FsProvider)
    provider_name = provider_class.get_name()
    if provider_name in __PROVIDER_CLASSES:
        raise KeyError("Provider %s already registered." % provider_name)
    else:
        __PROVIDER_CLASSES[provider_name] = provider_class


def get_provider_class(provider_name: str):
    """Get filesystem provider class by name"""
    return __PROVIDER_CLASSES[provider_name]


register_provider_class(LocalFsProvider)
register_provider_class(BlindFsProvider)

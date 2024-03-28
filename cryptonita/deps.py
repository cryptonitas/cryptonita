import importlib


class _deps_null_module:
    def __init__(self, dependency):
        self.dependency = dependency

    def __getattr__(self, attr):
        raise AttributeError(
            "'{}' not installed. You may install it running 'pip install cryptonita[full]'."
            .format(self.dependency)
        )


def importdep(name):
    try:
        return importlib.import_module(name)
    except ImportError:
        return _deps_null_module(name)

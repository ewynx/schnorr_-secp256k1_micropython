class _Subscriptable:

    def __getitem__(self, sub):
        return None

_SubSingleton = _Subscriptable()

Optional = _SubSingleton
Tuple = _SubSingleton

def cast(typ, val):
    return val


def _overload_dummy(*args, **kwds):
    """Helper for @overload to raise when called."""
    raise NotImplementedError(
        "You should not call an overloaded function. "
        "A series of @overload-decorated functions "
        "outside a stub module should always be followed "
        "by an implementation that is not @overload-ed."
    )


def overload(fun):
    return _overload_dummy

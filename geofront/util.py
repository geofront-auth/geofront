""":mod:`geofront.util` --- Utilities
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

"""
import functools
import inspect
import types

__all__ = {'typed'}


def typed(function: types.FunctionType) -> types.FunctionType:
    """Automatically check argument types using function's annotated
    parameters.  For example, the following code will raise :exc:`TypeError`:

    >>> @typed
    ... def add(a: int, b: int):
    ...     return a + b
    ...
    >>> add('strings are not ', 'accepted')

    :param function: a function to make automatically type checked
    :type function: :class:`types.FunctionType`

    """
    if not isinstance(function, types.FunctionType):
        raise TypeError('expected a function, not ' + repr(function))
    sig = inspect.signature(function)
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        annotations = function.__annotations__
        for param, arg in sig.bind(*args, **kwargs).arguments.items():
            try:
                cls = annotations[param]
            except KeyError:
                continue
            else:
                if not (isinstance(arg, cls) or
                        arg is sig.parameters[param].default):
                    raise TypeError(
                        '{0} must be an instance of {1.__module__}.'
                        '{1.__qualname__}, not {2!r}'.format(param, cls, arg)
                    )
        return function(*args, **kwargs)
    return wrapped
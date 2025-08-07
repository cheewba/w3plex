import asyncio
import inspect
import warnings
from functools import wraps
from inspect import isawaitable
from typing import (
    Any, Callable, ParamSpec, TypeVar, overload, Awaitable, cast,
)


P = ParamSpec("P")
R = TypeVar("R")
T = TypeVar("T", bound=type[Any])

_DEFAULT_DEPRECATED_MSG = "is deprecated and will be removed in a future version."


@overload
def deprecated(func_or_msg: Callable[P, R] | T, /) -> Callable[P, R] | T: ...
@overload
def deprecated(func_or_msg: str, /) -> Callable[[Callable[P, R] | T], Callable[P, R] | T]: ...
def deprecated(func_or_msg: Callable[P, R] | T | str, /) -> Any:
    """
    Use as:

      @deprecated
      def f(...): ...

      @deprecated("use g() instead")
      def f(...): ...

      @deprecated
      class C: ...

      @deprecated("use D instead")
      class C: ...
    """
    if isinstance(func_or_msg, str):
        message = func_or_msg
        def deco(obj: Callable[P, R] | T) -> Callable[P, R] | T:
            return _decorate(obj, message)
        return deco
    else:
        # used as @deprecated without arguments
        return _decorate(func_or_msg, _DEFAULT_DEPRECATED_MSG)


def _decorate(obj: Callable[P, R] | T, message: str) -> Callable[P, R] | T:
    if inspect.isclass(obj):
        return _decorate_class(obj, message)
    if callable(obj):
        return _decorate_func(obj, message)
    raise TypeError("deprecated can only decorate functions or classes")


def _decorate_func(func: Callable[P, R]) -> Callable[P, R]:
    # capture message via closure
    message = _DEFAULT_DEPRECATED_MSG
    if hasattr(_decorate_func, "__message__"):
        message = getattr(_decorate_func, "__message__")  # just in case
    @wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        warnings.warn(
            f"{func.__qualname__} {message}",
            DeprecationWarning,
            stacklevel=2,
        )
        return func(*args, **kwargs)
    # stash to keep tools happy (not required)
    wrapper.__deprecated__ = True  # type: ignore[attr-defined]
    return wrapper  # type: ignore[return-value]


def _decorate_class(cls: T, message: str) -> T:
    # Warn on instantiation by wrapping __init__ (even if it was object.__init__)
    orig_init = getattr(cls, "__init__", object.__init__)

    @wraps(orig_init)
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        warnings.warn(
            f"{cls.__qualname__} {message}",
            DeprecationWarning,
            stacklevel=2,
        )
        return orig_init(self, *args, **kwargs)

    setattr(cls, "__init__", __init__)
    # Optionally, mark class metadata
    try:
        cls.__deprecated__ = True  # type: ignore[attr-defined]
        cls.__doc__ = (cls.__doc__ or "").rstrip() + f"\n\n.. deprecated::\n   {message}\n"
    except Exception:
        pass
    return cls


class AttrDict(dict):
    def __getattr__(self, name):
        if name in self:
            return self[name]
        super().__getattribute__(name)


def as_future[R](value: R | Awaitable[R]) -> asyncio.Future[R]:
    if isawaitable(value):
        return asyncio.ensure_future(value)

    fut = asyncio.Future()
    fut.set_result(value)
    return cast(asyncio.Future[T], fut)
import asyncio
import inspect
import warnings
from collections.abc import Awaitable, Callable
from functools import wraps
from inspect import isawaitable
from typing import (
    Any,
    Protocol,
    cast,
    overload,
)

_DEFAULT_DEPRECATED_MSG = "is deprecated and will be removed in a future version."


class _DeprecatedDecorator(Protocol):
    def __call__[F: Callable[..., Any]](self, obj: F, /) -> F: ...


@overload
def deprecated[F: Callable[..., Any]](func_or_msg: F, /) -> F: ...
@overload
def deprecated(func_or_msg: str, /) -> _DeprecatedDecorator: ...
def deprecated(func_or_msg: Callable[..., Any] | str, /) -> Any:
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

        def deco[F: Callable[..., Any]](obj: F) -> F:
            return _decorate(obj, message)

        return deco
    else:
        # used as @deprecated without arguments
        return _decorate(func_or_msg, _DEFAULT_DEPRECATED_MSG)


def _decorate[F: Callable[..., Any]](obj: F, message: str) -> F:
    if inspect.isclass(obj):
        return cast(F, _decorate_class(obj, message))
    if callable(obj):
        return cast(F, _decorate_func(obj, message))
    raise TypeError("deprecated can only decorate functions or classes")


def _decorate_func[**P, R](func: Callable[P, R], message: str) -> Callable[P, R]:
    @wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        warnings.warn(
            f"{func.__qualname__} {message}",
            DeprecationWarning,
            stacklevel=2,
        )
        return func(*args, **kwargs)

    # stash to keep tools happy (not required)
    cast(Any, wrapper).__deprecated__ = True
    return wrapper


def _decorate_class[T: type[Any]](cls: T, message: str) -> T:
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

    cls.__init__ = __init__
    # Optionally, mark class metadata
    try:
        cast(Any, cls).__deprecated__ = True
        cls.__doc__ = (
            cls.__doc__ or ""
        ).rstrip() + f"\n\n.. deprecated::\n   {message}\n"
    except (AttributeError, TypeError):
        pass
    return cls


class AttrDict(dict):
    def __getattr__(self, name):
        if name in self:
            return self[name]
        return super().__getattribute__(name)


def as_future[R](value: R | Awaitable[R]) -> asyncio.Future[R]:
    if isawaitable(value):
        return asyncio.ensure_future(value)

    fut: asyncio.Future[R] = asyncio.Future()
    fut.set_result(value)
    return fut

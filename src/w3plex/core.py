from typing import Callable

from lazyplex import Application, application as _application



def application(fn: Callable) -> Application: ...
def application(*, return_exceptions: bool = False) -> Callable[[Callable], Application]: ...
def application(*args, **kwargs):
    """ Wrapper around ``lazyplex.application`` that accepts function as argument only.

        Threre's no need to pass name of the application, since
        it's taken from the config file.
    """
    kwargs['application_class'] = Application
    if args and isinstance(args[0], Callable):
        return _application(**kwargs)(args[0])
    return _application(*args, **kwargs)
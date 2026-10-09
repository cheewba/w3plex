from ..modules.proxy import ProxyPool
from ..utils import deprecated


@deprecated("use w3plex.modules.proxy.ProxyPool instead")
class ProxyService(ProxyPool):
    """Compatibility name for the proxy pool."""

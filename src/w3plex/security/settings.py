"""Strict public settings; no YAML factories, credentials or signing backends."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

from yarl import URL

from .errors import PermissionDenied


class ExecutionMode(StrEnum):
    EXECUTE = "execute"
    PLAN = "plan"


class PermissionLevel(StrEnum):
    ASK = "ask"
    POLICY = "policy"
    AUTO = "auto"


@dataclass(frozen=True)
class NetworkSettings:
    chain_id: int
    rpc_origin: str
    rpc_path: str
    credential_id: str | None = None


@dataclass(frozen=True)
class ProtectedSettings:
    networks: tuple[NetworkSettings, ...] = ()
    mode: ExecutionMode = ExecutionMode.EXECUTE
    permissions: PermissionLevel = PermissionLevel.ASK
    idle_seconds: int = 900
    model_registration: str | None = None


def parse_settings(
    value: Mapping, *, registered_models: frozenset[str]
) -> ProtectedSettings:
    """The host supplies its registered model names, never import paths."""
    if not isinstance(value, Mapping) or not set(value) <= {
        "networks",
        "mode",
        "permissions",
        "idle_seconds",
        "model_registration",
        "signing_backend",
    }:
        raise PermissionDenied()
    if value.get("signing_backend", "local") != "local":
        raise PermissionDenied()
    idle = value.get("idle_seconds", 900)
    if type(idle) is not int or not 1 <= idle <= 86400:
        raise PermissionDenied()
    model = value.get("model_registration")
    if model is not None and (
        not isinstance(model, str) or model not in registered_models
    ):
        raise PermissionDenied()
    networks = value.get("networks", [])
    if not isinstance(networks, list) or len(networks) > 64:
        raise PermissionDenied()
    output = []
    for network in networks:
        if (
            not isinstance(network, dict)
            or not {"chain_id", "rpc_origin", "rpc_path"} <= set(network)
            or not set(network)
            <= {"chain_id", "rpc_origin", "rpc_path", "credential_id"}
        ):
            raise PermissionDenied()
        chain = network["chain_id"]
        if type(chain) is not int or not 1 <= chain < 2**64:
            raise PermissionDenied()
        if not isinstance(network["rpc_origin"], str) or not isinstance(
            network["rpc_path"], str
        ):
            raise PermissionDenied()
        origin_valid = False
        url = URL()
        try:
            url = URL(network["rpc_origin"])
            origin_valid = (
                url.scheme == "https"
                and bool(url.host)
                and url.user is None
                and url.password is None
                and url.path in {"", "/"}
                and not url.query_string
                and not url.fragment
            )
        except ValueError:
            pass
        if not origin_valid:
            raise PermissionDenied()
        path = network["rpc_path"]
        if (
            not path.startswith("/")
            or path.startswith("//")
            or "?" in path
            or "#" in path
        ):
            raise PermissionDenied()
        credential = network.get("credential_id")
        if credential is not None and (
            not isinstance(credential, str)
            or re.fullmatch(r"[a-f0-9]{32}", credential) is None
        ):
            raise PermissionDenied()
        if ("{credential}" in path) != (credential is not None):
            raise PermissionDenied()
        output.append(NetworkSettings(chain, str(url), path, credential))
    valid = False
    mode = ExecutionMode.EXECUTE
    permissions = PermissionLevel.ASK
    try:
        mode = ExecutionMode(value.get("mode", "execute"))
        permissions = PermissionLevel(value.get("permissions", "ask"))
        valid = True
    except (ValueError, TypeError):
        pass
    if not valid:
        raise PermissionDenied()
    return ProtectedSettings(tuple(output), mode, permissions, idle, model)

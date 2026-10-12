"""Strict public settings reject factories, credentials and delegated signing."""

import pytest

from w3plex.security.errors import PermissionDenied
from w3plex.security.settings import ExecutionMode, PermissionLevel, parse_settings


def test_defaults_and_typed_secret_references():
    settings = parse_settings({}, registered_models=frozenset())
    assert settings.mode is ExecutionMode.EXECUTE
    assert settings.permissions is PermissionLevel.ASK
    assert settings.idle_seconds == 900
    assert settings.networks == ()
    settings = parse_settings(
        {
            "networks": [
                {
                    "chain_id": 1,
                    "rpc_origin": "https://rpc.example",
                    "rpc_path": "/v1/{credential}",
                    "credential_id": "ab" * 16,
                }
            ],
            "model_registration": "registered-model",
            "permissions": "auto",
        },
        registered_models=frozenset({"registered-model"}),
    )
    assert settings.networks[0].credential_id == "ab" * 16
    assert settings.permissions is PermissionLevel.AUTO


@pytest.mark.parametrize(
    "value",
    [
        {"__init__": "arbitrary:factory"},
        {"signing_backend": "hardware"},
        {"signing_backend": "external"},
        {"password": "secret"},
        {"idle_seconds": True},
        {"mode": "shell"},
        {"permissions": "unknown"},
        {"model_registration": "arbitrary:factory"},
        {
            "networks": [
                {"chain_id": True, "rpc_origin": "https://rpc.example", "rpc_path": "/"}
            ]
        },
        {
            "networks": [
                {
                    "chain_id": 1,
                    "rpc_origin": "https://user:password@rpc.example",
                    "rpc_path": "/",
                }
            ]
        },
    ],
)
def test_factories_credentials_and_excluded_backends_are_rejected(value):
    with pytest.raises(PermissionDenied):
        parse_settings(value, registered_models=frozenset())


@pytest.mark.parametrize(
    "backend",
    [
        "external",
        "hardware",
        "ledger",
        "remote",
        "https://PUBLIC-TEST-secret.example",
        {"kind": "local"},
        None,
        True,
    ],
)
def test_only_local_software_signing_settings_are_admitted(backend):
    with pytest.raises(PermissionDenied) as raised:
        parse_settings({"signing_backend": backend}, registered_models=frozenset())
    assert str(raised.value) == "permission_denied"
    assert raised.value.__cause__ is None and raised.value.__context__ is None


def test_explicit_local_settings_use_no_backend_or_device_factory():
    assert parse_settings(
        {"signing_backend": "local"}, registered_models=frozenset()
    ) == parse_settings({}, registered_models=frozenset())


@pytest.mark.parametrize(
    "origin",
    [
        "https://rpc.example:PUBLIC-TEST-secret",
        "https://[PUBLIC-TEST-secret",
        "https://user:PUBLIC-TEST-secret@rpc.example",
    ],
)
def test_credential_bearing_malformed_origins_return_only_safe_error(origin):
    with pytest.raises(PermissionDenied) as raised:
        parse_settings(
            {"networks": [{"chain_id": 1, "rpc_origin": origin, "rpc_path": "/"}]},
            registered_models=frozenset(),
        )
    assert "PUBLIC-TEST-secret" not in str(raised.value)
    assert raised.value.__cause__ is None and raised.value.__context__ is None

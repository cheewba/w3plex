import asyncio

import pytest

from w3plex.utils.dist import AttrDict, as_future, deprecated


def test_deprecated_function_preserves_custom_message_and_result():
    @deprecated("use replacement()")
    def legacy(value: int) -> int:
        return value + 1

    with pytest.warns(DeprecationWarning, match=r"legacy use replacement\(\)"):
        assert legacy(2) == 3
    assert legacy.__name__ == "legacy"


def test_deprecated_class_preserves_initialization():
    @deprecated("use NewClass")
    class Legacy:
        def __init__(self, value: int):
            self.value = value

    with pytest.warns(DeprecationWarning, match="Legacy use NewClass"):
        assert Legacy(3).value == 3


def test_deprecated_without_message():
    @deprecated
    def legacy():
        return "result"

    with pytest.warns(DeprecationWarning, match="is deprecated"):
        assert legacy() == "result"


def test_attr_dict_exposes_values_and_raises_for_missing_attributes():
    values = AttrDict(answer=42)
    assert values.answer == 42
    with pytest.raises(AttributeError, match="missing"):
        _ = values.missing


def test_as_future_handles_values_coroutines_and_existing_futures():
    async def check():
        async def result():
            return 7

        assert await as_future(0) == 0
        assert await as_future(result()) == 7
        existing = asyncio.get_running_loop().create_future()
        existing.set_result("value")
        assert as_future(existing) is existing

    asyncio.run(check())

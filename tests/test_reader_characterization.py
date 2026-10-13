"""Reader behavior recorded before adding SecretRef support (8e6a2b2)."""

import asyncio

import pytest
from eth_account import Account as EthAccount

from w3plex.utils.loader import FileLoader, accounts_loader, wallets_loader


def test_lines_trim_whitespace_and_skip_blank_comments(tmp_path):
    source = tmp_path / "lines.txt"
    source.write_bytes(b"\xef\xbb\xbf  # ignored\r\n\r\n  one \r\n\ttwo\t\n")
    assert asyncio.run(FileLoader(file=str(source)).process()) == ["one", "two"]


def test_filter_sees_original_line_and_transform_can_return_none(tmp_path):
    source = tmp_path / "lines.txt"
    source.write_text("one\n  two \nthree\n")
    loader = FileLoader(file=str(source), filter="^  ")
    assert asyncio.run(loader.process()) == ["two"]
    assert asyncio.run(FileLoader(file=str(source)).process(lambda _: None)) == []


def test_transform_error_and_missing_file_are_not_hidden(tmp_path):
    source = tmp_path / "lines.txt"
    source.write_text("bad integer\n")
    with pytest.raises(ValueError):
        asyncio.run(FileLoader(file=str(source)).process(int))
    with pytest.raises(FileNotFoundError):
        asyncio.run(FileLoader(file=str(tmp_path / "missing")).process())


def test_accounts_and_wallets_loader_keep_legacy_types(tmp_path):
    from w3ext import Account

    source = tmp_path / "keys.txt"
    source.write_text("01" * 32 + "\n")
    accounts = asyncio.run(accounts_loader(file=str(source))())
    assert type(accounts[0]) is Account
    assert accounts[0].address == EthAccount.from_key("01" * 32).address
    assert accounts[0].key.hex() == "01" * 32
    source.write_text(accounts[0].address.lower() + "\n")
    assert asyncio.run(wallets_loader(file=str(source))) == [accounts[0].address]

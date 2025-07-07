#!/usr/bin/env python3
"""secure.py - Password-protected keystore -> transparent encrypted I/O.

Scenario
========
1. Plain files open normally.
2. `encrypt_file(path, password=...)` encrypts a plaintext file with a
   *file-specific* password and stores the resulting key in an encrypted
   keystore so the password is never asked for again on the same
   machine.
3. The keystore (JSON list of base-64 keys) is itself encrypted with a
   *master* password prompted **once** per interpreter session.
4. `open(path)` in read-mode:
   * If plaintext -> built-in `open`.
   * If header `b"ENC1"` -> try keys from the decrypted keystore; if
     none succeed, ask for the file password, decrypt, remember the new
     key, and return a BytesIO/TextIOWrapper with plaintext.

Only **pure read** modes are intercepted; write/append/update are
forwarded untouched, so existing code is unaffected.
"""
import base64
import builtins
import getpass
import io
import json
import os
from hashlib import sha256, scrypt
from pathlib import Path
from typing import List, Optional, Union, Tuple

from cryptography.fernet import Fernet, InvalidToken

# ----------------------------------------------------------------------
# Paths & constants
# ----------------------------------------------------------------------
_MAGIC = b"ENC1"                      # header for encrypted *files*
_KS_MAGIC = b"KS01"                   # header for encrypted *keystore*
# TODO: think about customized keystore path
_KEYSTORE_PATH = Path.home() / ".keystore.bin"
_SALT_LEN = 16                        # bytes reserved for salt at file start

# scrypt work factors (adjust to taste)
_SCRYPT_N = 2 ** 15
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_WORK: Tuple[int, int, int] | None = None  # will hold the actual (N,r,p)

# ----------------------------------------------------------------------
# Salt handling (salt lives as first 16 bytes of keystore)
# ----------------------------------------------------------------------
_salt: bytes | None = None


def _get_salt() -> bytes:
    """Return application salt, create it once if keystore is absent."""

    global _salt
    if _salt is not None:
        return _salt

    if _KEYSTORE_PATH.exists():
        _salt = _KEYSTORE_PATH.read_bytes()[:_SALT_LEN]
        if len(_salt) == _SALT_LEN:
            return _salt  # happy path

    _salt = os.urandom(_SALT_LEN)
    return _salt


# ----------------------------------------------------------------------
# Master key (session‑cached)
# ----------------------------------------------------------------------
_master_key: bytes | None = None


def _adaptive_scrypt(password: str) -> bytes:
    """Try scrypt with decreasing N until it fits available RAM."""

    global _SCRYPT_WORK
    n = _SCRYPT_N
    while n >= 2 ** 12:  # 4096 is ~4 MiB with r=8
        try:
            key = scrypt(
                password.encode(),
                salt=_get_salt(),
                n=n,
                r=_SCRYPT_R,
                p=_SCRYPT_P,
                dklen=32,
            )
            _SCRYPT_WORK = (n, _SCRYPT_R, _SCRYPT_P)
            return key
        except ValueError as exc:
            msg = str(exc).lower()
            if "memory limit exceeded" in msg or "not enough memory" in msg:
                n //= 2  # halve N and retry
                continue
            raise  # other failures propagate

    raise MemoryError("Unable to derive master key: scrypt N fell below 2**12")


def _get_master_key() -> bytes:
    global _master_key
    if _master_key is None:
        pwd = getpass.getpass("Master password: ")
        _master_key = _adaptive_scrypt(pwd)
    return _master_key


# ----------------------------------------------------------------------
# Keystore helpers (JSON list of base‑64 keys, encrypted with master key)
# ----------------------------------------------------------------------

def _raw_keystore_bytes() -> bytes:
    """Keystore content without the leading salt (may be empty)."""

    if not _KEYSTORE_PATH.exists():
        return b""
    buf = _KEYSTORE_PATH.read_bytes()
    if len(buf) < _SALT_LEN:
        raise ValueError("Keystore too small / corrupt")
    return buf[_SALT_LEN:]


def _load_keystore() -> List[str]:
    """Return stored keys as base-64 strings."""

    raw = _raw_keystore_bytes()
    if not raw:
        return []

    # legacy plaintext keystore (no magic marker)
    if not raw.startswith(_KS_MAGIC):
        try:
            return json.loads(raw.decode())["keys"]
        except (json.JSONDecodeError, KeyError):
            return []

    cipher = raw[len(_KS_MAGIC):]
    f = Fernet(base64.urlsafe_b64encode(_get_master_key()))
    try:
        plain = f.decrypt(cipher)
        return json.loads(plain.decode())["keys"]
    except InvalidToken as exc:
        raise ValueError("Wrong master password for keystore") from exc


def _save_keystore(keys: List[str]) -> None:
    """Write keys list back to disk (salt + magic + ciphertext)."""

    data = json.dumps({"keys": keys}).encode()
    f = Fernet(base64.urlsafe_b64encode(_get_master_key()))
    token = f.encrypt(data)

    payload = _get_salt() + _KS_MAGIC + token
    _KEYSTORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _KEYSTORE_PATH.write_bytes(payload)


def _all_keys() -> List[bytes]:
    return [base64.urlsafe_b64decode(k) for k in _load_keystore()]


def _add_key(raw_key: bytes) -> None:
    keys = _load_keystore()
    b64 = base64.urlsafe_b64encode(raw_key).decode()
    if b64 not in keys:
        keys.append(b64)
        _save_keystore(keys)


# ----------------------------------------------------------------------
# File‑password → key derivation (SHA‑256 for demo simplicity)
# ----------------------------------------------------------------------

def _derive_file_key(password: str) -> bytes:
    return sha256(password.encode()).digest()


# ----------------------------------------------------------------------
# Public helper: encrypt_file
# ----------------------------------------------------------------------

def encrypt_file(
    src: Union[str, Path],
    *,
    password: Optional[str] = None,
    dst: Optional[Union[str, Path]] = None,
    inplace: bool = False,
    add_to_keystore: bool = False,
) -> Path:
    """Encrypt *src* with a file-specific password and cache its key."""

    src_path = Path(src)
    data = src_path.read_bytes()
    if data.startswith(_MAGIC):
        raise ValueError(f"{src_path} is already encrypted")

    pwd = password or getpass.getpass(f"Password for {src_path}: ")
    key = _derive_file_key(pwd)

    cipher = Fernet(base64.urlsafe_b64encode(key)).encrypt(data)
    out_bytes = _MAGIC + cipher

    if inplace:
        dst_path = src_path
    else:
        dst_path = Path(dst) if dst else src_path.with_suffix(src_path.suffix + ".enc")

    dst_path.write_bytes(out_bytes)

    if add_to_keystore:
        _add_key(key)
    return dst_path


def decrypt_file(
    src: Union[str, Path],
    *,
    password: Optional[str] = None,
    dst: Optional[Union[str, Path]] = None,
    inplace: bool = False,
) -> Path:
    """Decrypt an `ENC1` file to plaintext.

    Parameters
    ----------
    src : str | Path
        Path to the encrypted file.
    password : str, optional
        File password; if omitted the function tries cached keys and
        prompts only if necessary.
    dst : str | Path, optional
        Destination path for the plaintext. Ignored if ``inplace`` is
        True.
    inplace : bool, default ``False``
        If True, overwrite *src* with its plaintext.
    """

    src_path = Path(src)
    raw = src_path.read_bytes()
    if not raw.startswith(_MAGIC):
        raise ValueError(f"{src_path} is not encrypted")

    cipher = raw[len(_MAGIC):]

    # 1) try cached keys
    plain: Optional[bytes] = None
    for k in _all_keys():
        try:
            plain = Fernet(base64.urlsafe_b64encode(k)).decrypt(cipher)
            break
        except InvalidToken:
            continue

    # 2) fallback to provided or prompted password
    if plain is None:
        pwd = password or getpass.getpass(f"Password for {src_path}: ")
        k = _derive_file_key(pwd)
        try:
            plain = Fernet(base64.urlsafe_b64encode(k)).decrypt(cipher)
        except InvalidToken as exc:
            raise ValueError("Wrong password") from exc

    dst_path = src_path if inplace else (
        Path(dst) if dst else src_path.with_suffix(".dec")
    )
    dst_path.write_bytes(plain)
    return dst_path


# ----------------------------------------------------------------------
# Decryption helper used by patched open
# ----------------------------------------------------------------------

def _decrypt_if_needed(path: Path, raw: bytes, *, text_encoding: Optional[str]):
    """Return file-like object with plaintext; None if *raw* is plain."""

    if not raw.startswith(_MAGIC):
        return None  # original file is plaintext

    cipher = raw[len(_MAGIC):]

    # Try cached keys first
    for k in _all_keys():
        try:
            plain = Fernet(base64.urlsafe_b64encode(k)).decrypt(cipher)
            break
        except InvalidToken:
            continue
    else:
        # Need file password
        pwd = getpass.getpass(f"Password for {path}: ")
        k = _derive_file_key(pwd)
        try:
            plain = Fernet(base64.urlsafe_b64encode(k)).decrypt(cipher)
        except InvalidToken as exc:
            raise ValueError(f"Wrong password for file {path}") from exc
        _add_key(k)

    buf = io.BytesIO(plain)
    return buf if text_encoding is None else io.TextIOWrapper(buf, encoding=text_encoding)


# ----------------------------------------------------------------------
# Patched built‑in open (intercepts read‑only modes)
# ----------------------------------------------------------------------
_orig_open = builtins.open


def _secure_open(
    file,  # positional name preserved for compatibility
    mode: str = "r",
    buffering: int = -1,
    encoding: Optional[str] = None,
    errors=None,
    newline=None,
    closefd=True,
    opener=None,
):
    """Transparent decryption for `ENC1` files when opened read-only."""

    if set(mode) - {"r", "b", "t"}:  # any write / update flag present
        return _orig_open(file, mode, buffering, encoding, errors, newline, closefd, opener)

    p = Path(file)
    raw = _orig_open(file, "rb").read()

    replacement = _decrypt_if_needed(p, raw, text_encoding=None if "b" in mode else encoding)
    if replacement is None:
        return _orig_open(file, mode, buffering, encoding, errors, newline, closefd, opener)
    return replacement


# Patch builtins once
builtins.open = _secure_open

__all__ = [
    "encrypt_file",
    "_secure_open",
]

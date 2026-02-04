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
import secrets
from hashlib import sha256, scrypt
from pathlib import Path
from typing import List, Optional, Union, Tuple
from sys import stdout

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


class SecureError(Exception):
    pass


class IncorrectPassword(SecureError):
    pass


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
    unlock_keystore()
    return _master_key


def unlock_keystore():
    global _master_key
    if _master_key is None:
        pwd = getpass.getpass("Master password: ")
        if not _keystore_exists():
            pwd_confirm = getpass.getpass("Master password confirm: ")
            if not pwd == pwd_confirm:
                raise IncorrectPassword("Master passwords don't match")
        _master_key = _adaptive_scrypt(pwd)


# ----------------------------------------------------------------------
# Keystore helpers (JSON list of base‑64 keys, encrypted with master key)
# ----------------------------------------------------------------------

def _keystore_exists() -> bool:
    return _KEYSTORE_PATH.exists()

def _raw_keystore_bytes() -> bytes:
    """Keystore content without the leading salt (may be empty)."""

    if not _keystore_exists():
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
        global _master_key
        _master_key = None

        raise IncorrectPassword("Wrong master password for keystore") from exc


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
# Core encryption/decryption helpers
# ----------------------------------------------------------------------

def _encrypt_bytes(
    data: bytes,
    password: str,
    *,
    add_to_keystore: bool = False,
) -> bytes:
    """Encrypt bytes and return data with MAGIC prefix.

    Args:
        data: Bytes to encrypt
        password: Required password for encryption
        add_to_keystore: If True, add derived key to keystore
    """
    key = _derive_file_key(password)
    cipher = Fernet(base64.urlsafe_b64encode(key)).encrypt(data)

    if add_to_keystore:
        _add_key(key)

    return _MAGIC + cipher


def _decrypt_bytes(
    data: bytes,
    *,
    password: Optional[str] = None,
    use_keystore: bool = True,
    ask_password: bool = False,
    prompt_context: str = "data",
) -> bytes:
    """Decrypt bytes with MAGIC prefix, trying keystore first.

    Args:
        data: Encrypted bytes with MAGIC prefix
        password: Optional password for decryption
        use_keystore: Try cached keys from keystore
        ask_password: If True and no password/keystore match, prompt; else raise
        prompt_context: Context string for password prompt
    """
    if not data.startswith(_MAGIC):
        raise ValueError(f"{prompt_context} is not encrypted")

    cipher = data[len(_MAGIC):]

    plain: Optional[bytes] = None
    if use_keystore and not password:
        for k in _all_keys():
            try:
                plain = Fernet(base64.urlsafe_b64encode(k)).decrypt(cipher)
                break
            except InvalidToken:
                continue

    if plain is None:
        if password:
            k = _derive_file_key(password)
        elif ask_password:
            pwd = getpass.getpass(f"Password for {prompt_context}: ")
            k = _derive_file_key(pwd)
        else:
            raise IncorrectPassword("No password provided and key not in keystore")

        try:
            plain = Fernet(base64.urlsafe_b64encode(k)).decrypt(cipher)
        except InvalidToken as exc:
            raise IncorrectPassword("Wrong password") from exc

        if not password and use_keystore:
            _add_key(k)

    return plain


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
    out_bytes = _encrypt_bytes(data, password=pwd, add_to_keystore=add_to_keystore)

    if inplace:
        dst_path = src_path
    else:
        dst_path = Path(dst) if dst else src_path.with_suffix(src_path.suffix + ".enc")

    dst_path.write_bytes(out_bytes)
    return dst_path


def decrypt_file(
    src: Union[str, Path],
    *,
    password: Optional[str] = None,
    dst: Optional[Union[str, Path]] = None,
    inplace: bool = False,
    use_keystore: bool = False,
) -> Path:
    """Decrypt an `ENC1` file to plaintext."""
    src_path = Path(src)
    raw = src_path.read_bytes()

    plain = _decrypt_bytes(
        raw,
        password=password,
        use_keystore=use_keystore,
        ask_password=True,
        prompt_context=str(src_path)
    )

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
        return None

    plain = _decrypt_bytes(
        raw,
        use_keystore=True,
        ask_password=True,
        prompt_context=str(path)
    )

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

    attempts = 3
    while True:
        try:
            replacement = _decrypt_if_needed(p, raw, text_encoding=None if "b" in mode else encoding)
            break
        except IncorrectPassword as e:
            attempts -= 1
            if attempts <= 0:
                raise

            stdout.write(f"{e}, {attempts} attempts left\r\n")
            stdout.flush()


    if replacement is None:
        return _orig_open(file, mode, buffering, encoding, errors, newline, closefd, opener)

    return replacement


# Patch builtins once
builtins.open = _secure_open


# ----------------------------------------------------------------------
# Data encryption/decryption (for in-memory or stream data)
# ----------------------------------------------------------------------

def encrypt_data(
    data: Union[str, bytes],
    *,
    password: Optional[str] = None,
    add_to_keystore: bool = True,
) -> Tuple[str, str]:
    """Encrypt data and return (encrypted_data, password).

    Args:
        data: String or bytes to encrypt
        password: Optional password; if None, generates random password
        add_to_keystore: If True, add derived key to keystore (default: True)

    Returns:
        Tuple of (base64-encoded encrypted data, password used)

    Raises:
        ValueError: If neither password nor add_to_keystore is provided
    """
    if password is None and not add_to_keystore:
        raise ValueError("Either password must be provided or add_to_keystore must be True")

    if isinstance(data, str):
        data = data.encode('utf-8')

    if password is None:
        password = secrets.token_urlsafe(32)

    encrypted_bytes = _encrypt_bytes(data, password, add_to_keystore=add_to_keystore)
    return base64.b64encode(encrypted_bytes).decode('ascii'), password


def decrypt_data(
    encrypted: str,
    *,
    password: Optional[str] = None,
    use_keystore: bool = True,
) -> str:
    """Decrypt data that was encrypted with encrypt_data.

    Args:
        encrypted: Base64-encoded encrypted data
        password: Optional password for decryption
        use_keystore: Try cached keys from keystore

    Returns:
        Decrypted data as string

    Raises:
        IncorrectPassword: If decryption fails or no key available
    """
    try:
        raw = base64.b64decode(encrypted.encode('ascii'))
    except Exception:
        raise ValueError("Invalid base64-encoded data")

    if not raw.startswith(_MAGIC):
        return encrypted

    plain = _decrypt_bytes(
        raw,
        password=password,
        use_keystore=use_keystore,
        ask_password=False,
        prompt_context="encrypted data"
    )
    return plain.decode('utf-8')


__all__ = [
    "encrypt_file",
    "decrypt_file",
    "encrypt_data",
    "decrypt_data",
    "SecureError",
    "IncorrectPassword",
]

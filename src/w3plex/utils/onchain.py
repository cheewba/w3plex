def is_erc_address(address: str) -> bool:
    # ethereum address length is 20 bytes = 2 + 40 chars
    address = address.strip()
    return address.startswith('0x') and len(address) == 42


def is_erc_private_key(key: str) -> bool:
    # erc private key length is 32 bytes = 2 + 64 chars
    key = key.strip()
    return key.startswith('0x') and len(key) == 66
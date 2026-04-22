def normalize_key(key):
    if isinstance(key, int):
        return key
    if key is None:
        return 0
    if isinstance(key, str):
        key = key.strip()
        if key.startswith("0x"):
            return int(key, 16)
        try:
            return int(key, 16)
        except ValueError:
            return int(key)
    return int(key)


def int_to_bits(value, width):
    return format(value, f"0{width}b")


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

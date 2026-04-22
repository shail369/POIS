from Crypto.Cipher import AES

class AES_PRF:
    def __init__(self, key_hex):
        key = bytes.fromhex(key_hex)
        self.cipher = AES.new(key, AES.MODE_ECB)

    def F(self, x_hex):
        x = bytes.fromhex(x_hex.zfill(32))
        return self.cipher.encrypt(x).hex()
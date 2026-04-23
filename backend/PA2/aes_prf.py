"""
PA2/aes_prf.py
==============
AES-128 as a PRF: F_k(x) = AES_k(x)

Using PyCryptodome as the OS primitive, per the PA#2 specification.
"""

from Crypto.Cipher import AES

class AES_PRF:
    def __init__(self, key_hex):
        key = bytes.fromhex(key_hex.zfill(32))
        if len(key) != 16:
            raise ValueError("AES_PRF requires a 16-byte key")
        self._key = key
        self.cipher = AES.new(key, AES.MODE_ECB)

    def F(self, x_hex):
        """F_k(x) = AES_k(x)"""
        x = bytes.fromhex(x_hex.zfill(32))
        return self.cipher.encrypt(x).hex()

    def F_inv(self, y_hex):
        """F_k^{-1}(y) = AES_k^{-1}(y) — required for CPA decryption"""
        y = bytes.fromhex(y_hex.zfill(32))
        return self.cipher.decrypt(y).hex()

    def verify_fips197_kat(self):
        """FIPS-197 Appendix B known-answer test."""
        # Key: 2b7e151628aed2a6abf7158809cf4f3c, Pt: 3243f6a8885a308d313198a2e0370734
        prf = AES_PRF("2b7e151628aed2a6abf7158809cf4f3c")
        return prf.F("3243f6a8885a308d313198a2e0370734") == "3925841d02dc09fbdc118597196a0b32"

    def info(self):
        """Metadata for the React frontend."""
        return {
            "backend": "OS primitive — Crypto.Cipher.AES (PyCryptodome)",
            "key_hex": self._key.hex(),
            "fips197_kat_ok": self.verify_fips197_kat(),
            "note": "F_k(x) = AES_k(x) implemented via PyCryptodome",
        }
"""
PA2/aes_prf.py
==============
AES-128 used as a PRF / PRP plug-in (the "AES plug-in" required by PA#2).

Satisfies the project specification:
  "You may plug in AES as the concrete PRF. … Implement an alternative PRF
   using AES-128 directly: F_k(x) = AES_k(x)."

No external cryptographic libraries are used.  All AES logic lives in
aes_core.py, which is a pure-Python FIPS 197 implementation.

The one permitted exception (OS-level randomness) is NOT needed here;
everything is deterministic given key and input.
"""

import os
import sys

# Resolve the backend root so that aes_core can always be found,
# regardless of the working directory when the module is imported.
_BASE = os.path.dirname(os.path.abspath(__file__))

from aes_core import aes128_encrypt_block, aes128_decrypt_block


class AES_PRF:
    """
    Concrete PRF/PRP built from pure-Python AES-128.

    F_k(x) = AES_k(x)

    Per the PRF/PRP switching lemma, AES (a PRP) is computationally
    indistinguishable from a PRF when the domain is super-polynomial.

    Interface
    ---------
    AES_PRF(key_hex)  — 32-hex-char (16-byte) key
    .F(x_hex)         — 32-hex-char (16-byte) query  → 32-hex-char output
    .F_inv(x_hex)     — inverse (decryption) for PRP usage
    """

    def __init__(self, key_hex: str):
        raw = bytes.fromhex(key_hex.zfill(32))
        if len(raw) != 16:
            raise ValueError("AES_PRF requires a 16-byte (32 hex-char) key")
        self._key = raw

    def F(self, x_hex: str) -> str:
        """Encrypt one 16-byte block: F_k(x) = AES_k(x)."""
        x = bytes.fromhex(x_hex.zfill(32))
        if len(x) != 16:
            raise ValueError("AES_PRF.F requires a 16-byte (32 hex-char) input")
        ct = aes128_encrypt_block(self._key, x)
        return ct.hex()

    def F_inv(self, y_hex: str) -> str:
        """Decrypt one block (PRP inverse): AES_k^{-1}(y)."""
        y = bytes.fromhex(y_hex.zfill(32))
        if len(y) != 16:
            raise ValueError("AES_PRF.F_inv requires a 16-byte input")
        pt = aes128_decrypt_block(self._key, y)
        return pt.hex()


# ---------------------------------------------------------------------------
# Quick smoke-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import os as _os
    key_hex = _os.urandom(16).hex()          # OS randomness — the one permitted exception
    prf = AES_PRF(key_hex)

    x_hex = "00000000000000000000000000000000"
    ct = prf.F(x_hex)
    pt = prf.F_inv(ct)

    assert pt == x_hex, f"Round-trip failed: {pt} != {x_hex}"
    print(f"AES_PRF smoke test passed.")
    print(f"  key = {key_hex}")
    print(f"  F(0^128) = {ct}")
    print(f"  F_inv(ct) = {pt}")
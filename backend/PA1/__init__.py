"""
PA1 package — One-Way Functions & Pseudorandom Generators
=========================================================
Public exports:
  DLP_OWF   — Discrete-log one-way function  f(x) = g^x mod p
  PRG       — Iterative hard-core-bit PRG     G(x0) = b(x0) || b(x1) || ...
  OWF_from_PRG — Backward reduction: demonstrate f(s)=G(s) is a OWF
  frequency_test, runs_test, serial_test — NIST SP 800-22 randomness tests
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from owf import DLP_OWF
from prg import PRG
from owf_from_prg import OWF_from_PRG
from tests import frequency_test, runs_test, serial_test

__all__ = [
    "DLP_OWF",
    "PRG",
    "OWF_from_PRG",
    "frequency_test",
    "runs_test",
    "serial_test",
]

import sys
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, os.path.join(BASE_DIR, "../PA1"))

from prg import PRG
from owf import DLP_OWF

class GGM_PRF:
    def __init__(self):
        self.owf = DLP_OWF()

    def F(self, k, x):
        """
        k: key (int or string)
        x: bit string (e.g., "0101")
        """
        prg = PRG(self.owf)

        state = int(k)

        for bit in x:
            prg.seed(state)

            out = prg.next_bits(128)

            left = out[:64]
            right = out[64:]

            if bit == '0':
                state = int(left, 2)
            else:
                state = int(right, 2)

        return format(state, 'x')  # return hex
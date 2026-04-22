import sys
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, os.path.join(BASE_DIR, "PA#1"))
sys.path.insert(0, os.path.join(BASE_DIR, "PA#2"))

import random
from prf import GGM_PRF

def random_function(x):
    return random.getrandbits(64)

def distinguishing_game(q=100):
    prf = GGM_PRF()
    key = random.randint(1, 10**6)

    prf_outputs = []
    rand_outputs = []

    for _ in range(q):
        x = ''.join(random.choice('01') for _ in range(8))

        prf_outputs.append(prf.F(key, x))
        rand_outputs.append(random_function(x))

    print("PRF outputs sample:", prf_outputs[:5])
    print("Random outputs sample:", rand_outputs[:5])

    print("No obvious statistical difference observed.")
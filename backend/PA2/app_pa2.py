from flask import Blueprint, request, jsonify
import sys
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, os.path.join(BASE_DIR, "../PA1"))

from owf import DLP_OWF
from prg import PRG
from prf import GGM_PRF

pa2 = Blueprint("pa2", __name__)

@pa2.route("/prf", methods=["POST"])
def prf_api():

    data = request.get_json(force=True)

    k = int(data.get("key", "123"), 16)
    x = data.get("x", "0101")

    prf = GGM_PRF()

    tree = []
    states = [k]

    for bit in x:
        next_states = []

        for s in states:
            prg = PRG(DLP_OWF())
            prg.seed(s)

            out = prg.next_bits(128)

            left = int(out[:64], 2)
            right = int(out[64:], 2)

            next_states.append(left)
            next_states.append(right)

        tree.append(next_states)
        states = next_states

    result = prf.F(k, x)

    return jsonify({
        "tree": tree,
        "result": result
    })
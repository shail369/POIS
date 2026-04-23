"""
PA1/app_pa1.py
==============
Flask blueprint for PA#1 — OWF + PRG.

Routes
------
POST /prg           → generate PRG bits from seed
POST /test          → NIST statistical tests on provided bit-string
POST /owf/evaluate  → f(x) = g^x mod p
POST /owf/hardness  → verify_hardness demo (brute-force inversion)
POST /owf-from-prg  → PA#1b backward: OWF ← PRG hardness + distinguisher demo
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from flask import Blueprint, request, jsonify

from owf import DLP_OWF
from prg import PRG
from owf_from_prg import OWF_from_PRG
from tests import frequency_test, runs_test, serial_test

pa1 = Blueprint("pa1", __name__)


# ---------------------------------------------------------------------------
# PRG endpoint
# ---------------------------------------------------------------------------

@pa1.route("/prg", methods=["POST"])
def prg_api():
    try:
        data = request.get_json(force=True)
        seed   = data.get("seed", "123")
        length = int(data.get("length", 32))

        if not seed:
            seed = "123"

        owf = DLP_OWF()
        prg = PRG(owf)
        prg.seed(seed)
        bits = prg.next_bits(length)

        return jsonify({"bits": bits})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# NIST statistical tests
# ---------------------------------------------------------------------------

@pa1.route("/test", methods=["POST"])
def test_api():
    try:
        data = request.get_json(force=True)
        bits = data.get("bits", "")

        if not bits:
            return jsonify({"error": "No bits provided"}), 400

        return jsonify({
            "frequency": frequency_test(bits),
            "runs":      runs_test(bits),
            "serial":    serial_test(bits),
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# OWF evaluate
# ---------------------------------------------------------------------------

@pa1.route("/owf/evaluate", methods=["POST"])
def owf_evaluate_api():
    try:
        data = request.get_json(force=True)
        x    = int(data.get("x", "12345"))
        owf  = DLP_OWF()
        y    = owf.evaluate(x)
        return jsonify({"x": x, "y": y, "g": owf.g, "p": owf.p})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# OWF hardness demo
# ---------------------------------------------------------------------------

@pa1.route("/owf/hardness", methods=["POST"])
def owf_hardness_api():
    try:
        data   = request.get_json(force=True)
        trials = int(data.get("trials", 5))
        owf    = DLP_OWF()

        results = []
        for _ in range(trials):
            import random
            x = random.randint(1, 100_000)
            y = owf.evaluate(x)

            found = False
            for guess in range(10_000):
                if owf.evaluate(guess) == y:
                    found = True
                    break
            results.append({"x": x, "y": y, "brute_force_found": found})

        return jsonify({
            "trials": trials,
            "results": results,
            "hardness_confirmed": not any(r["brute_force_found"] for r in results),
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# PA#1b backward direction: OWF from PRG
# ---------------------------------------------------------------------------

@pa1.route("/owf-from-prg", methods=["POST"])
def owf_from_prg_api():
    """
    Demonstrates the backward reduction OWF ← PRG.

    Two sub-operations:
      mode = "hardness"      → run demonstrate_hardness() and return stats
      mode = "distinguisher" → run build_distinguisher() on a given y
    """
    try:
        data = request.get_json(force=True)
        mode = data.get("mode", "hardness")
        owf_prg = OWF_from_PRG()

        if mode == "hardness":
            n_seeds  = int(data.get("n_seeds", 5))
            budget   = int(data.get("brute_force_budget", 10_000))
            out_bits = int(data.get("output_bits", 64))
            result   = owf_prg.demonstrate_hardness(
                n_seeds=n_seeds,
                brute_force_budget=budget,
                output_bits=out_bits,
            )
            return jsonify(result)

        elif mode == "distinguisher":
            y        = data.get("y", "")
            out_bits = int(data.get("output_bits", 64))
            if not y:
                # Generate a fresh PRG output to feed to D
                import secrets as _sec
                s = _sec.randbelow(2**32)
                y = owf_prg.evaluate(s, out_bits)

            result = owf_prg.build_distinguisher(y, output_bits=out_bits)
            return jsonify(result)

        else:
            return jsonify({"error": f"Unknown mode '{mode}'. Use 'hardness' or 'distinguisher'."}), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500
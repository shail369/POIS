from flask import Blueprint, request, jsonify

from owf import DLP_OWF
from prg import PRG
from tests import frequency_test, runs_test, serial_test

pa1 = Blueprint("pa1", __name__)

@pa1.route("/prg", methods=["POST"])
def prg_api():
    try:
        data = request.get_json(force=True)

        seed = data.get("seed", "123")
        length = int(data.get("length", 32))

        if seed == "":
            seed = "123"

        owf = DLP_OWF()
        prg = PRG(owf)

        prg.seed(seed)
        bits = prg.next_bits(length)

        return jsonify({
            "bits": bits
        })

    except Exception as e:
        print("PRG ERROR:", str(e))
        return jsonify({"error": str(e)}), 500

@pa1.route("/test", methods=["POST"])
def test_api():
    try:
        data = request.get_json(force=True)

        bits = data.get("bits", "")

        if not bits:
            return jsonify({"error": "No bits provided"}), 400

        return jsonify({
            "frequency": frequency_test(bits),
            "runs": runs_test(bits),
            "serial": serial_test(bits)
        })

    except Exception as e:
        print("TEST ERROR:", str(e))
        return jsonify({"error": str(e)}), 500
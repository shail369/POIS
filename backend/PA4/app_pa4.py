from flask import Blueprint, request, jsonify
import secrets
import uuid

from modes import MODES
# from cpa_game import simulate_ind_cpa_dummy, simulate_rounds

pa4 = Blueprint("pa4", __name__)

@pa4.route("/pa4/encrypt", methods=["POST"])
def pa4_encrypt_api():
    data = request.get_json(force=True)

    mode = data.get("mode", "CBC")
    key = data.get("key", "1a2b3c4d")
    message = data.get("message", "")

    try:
        result = MODES.encrypt(mode, key, message.encode("utf-8"))
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@pa4.route("/pa4/decrypt", methods=["POST"])
def pa4_decrypt_api():
    data = request.get_json(force=True)

    mode = data.get("mode", "CBC")
    key = data.get("key", "1a2b3c4d")
    c_hex = data.get("ciphertext", "")
    iv_hex = data.get("iv")
    nonce_hex = data.get("nonce")

    if not c_hex:
        return jsonify({"error": "Missing ciphertext"}), 400

    try:
        kwargs = {}
        if iv_hex:
            kwargs["iv"] = bytes.fromhex(iv_hex)
        if nonce_hex:
            kwargs["nonce"] = bytes.fromhex(nonce_hex)

        msg = MODES.decrypt(mode, key, bytes.fromhex(c_hex), **kwargs)

        return jsonify({
            "message": msg.decode("utf-8", errors="replace"),
            "messageHex": msg.hex(),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@pa4.route("/pa4/trace", methods=["POST"])
def pa4_trace_api():
    data = request.get_json(force=True)

    mode = data.get("mode", "CBC")
    key = data.get("key", "1a2b3c4d")
    message = data.get("message", "")

    try:
        trace = MODES.trace_three_blocks(mode, key, message.encode("utf-8"))
        return jsonify(trace)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@pa4.route("/pa4/flip-bit", methods=["POST"])
def pa4_flip_bit_api():
    data = request.get_json(force=True)

    mode = data.get("mode", "CBC")
    key = data.get("key", "1a2b3c4d")
    message = data.get("message", "")
    block_index = int(data.get("blockIndex", 0))
    bit_index = int(data.get("bitIndex", 0))

    try:
        result = MODES.flip_bit_demo(
            mode,
            key,
            message.encode("utf-8"),
            block_index=block_index,
            bit_index=bit_index,
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@pa4.route("/pa4/attack/cbc-iv-reuse", methods=["POST"])
def pa4_attack_cbc_iv_reuse_api():
    data = request.get_json(force=True)

    key = data.get("key", "1a2b3c4d")
    message_a = data.get("messageA", "AAAAAAAABBBBBBBBCCCCCCCC")
    message_b = data.get("messageB", "AAAAAAAAXXXXXXXXYYYYYYYY")

    try:
        result = MODES.cbc_iv_reuse_demo(
            key,
            message_a.encode("utf-8"),
            message_b.encode("utf-8"),
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@pa4.route("/pa4/attack/ofb-keystream-reuse", methods=["POST"])
def pa4_attack_ofb_keystream_reuse_api():
    data = request.get_json(force=True)

    key = data.get("key", "1a2b3c4d")
    message_a = data.get("messageA", "hello stream one")
    message_b = data.get("messageB", "hello stream two")

    try:
        result = MODES.ofb_keystream_reuse_demo(
            key,
            message_a.encode("utf-8"),
            message_b.encode("utf-8"),
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
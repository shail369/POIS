from flask import Blueprint, request, jsonify
import sys
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA12"))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA14"))

from rsa import RSA
from pkcs15 import pkcs15_pad
from crt import hastad_attack

pa14 = Blueprint('pa14', __name__, url_prefix='/pa14')

@pa14.route('/hastad', methods=['POST'])
def hastad_demo():
    data = request.get_json() or {}
    message = data.get('message', 42)
    e = 3
    
    rsa = RSA()
    # Generate 3 keypairs
    keys = [rsa.keygen(bits=64) for _ in range(e)]
    moduli = [k["N"] for k in keys]
    ciphertexts = [rsa.encrypt(k["N"], e, message) for k in keys]
    
    x, recovered_m = hastad_attack(ciphertexts, moduli, e)
    
    return jsonify({
        "success": recovered_m == message,
        "original_message": message,
        "recovered_integer": str(x),
        "recovered_message": recovered_m,
        "ciphertexts": ciphertexts,
        "moduli": moduli
    })

@pa14.route('/hastad_padded', methods=['POST'])
def hastad_padded_demo():
    data = request.get_json() or {}
    message = data.get('message', 42)
    e = 3
    
    rsa = RSA()
    # Larger bit length for padding, e.g., 256 bits (32 bytes)
    keys = [rsa.keygen(bits=256) for _ in range(e)] 
    moduli = [k["N"] for k in keys]
    
    ciphertexts = []
    # Convert message to bytes
    m_bytes = message.to_bytes((message.bit_length() + 7) // 8 or 1, 'big')
    for k in keys:
        N = k["N"]
        k_bytes = (N.bit_length() + 7) // 8
        padded_m = pkcs15_pad(m_bytes, k_bytes)
        padded_m_int = int.from_bytes(padded_m, 'big')
        c = rsa.encrypt(N, e, padded_m_int)
        ciphertexts.append(c)
        
    x, recovered_m_int = hastad_attack(ciphertexts, moduli, e)
    
    return jsonify({
        "success": False,
        "recovered_integer": str(x),
        "recovered_message": recovered_m_int,
        "ciphertexts": ciphertexts,
        "moduli": moduli,
        "message": "Attack fails on padded RSA because ciphertexts don't share the same padded plaintext."
    })

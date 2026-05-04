from flask import Blueprint, request, jsonify
import sys
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA12"))
sys.path.insert(0, os.path.join(BASE_DIR, "../PA15"))

from rsa import RSA
from rsa_signature import sign, verify, sign_raw, verify_raw, verify_with_intermediates, verify_raw_with_intermediates

pa15 = Blueprint('pa15', __name__, url_prefix='/pa15')

# Store keys in memory for demo
keys = {}

@pa15.route('/keygen', methods=['POST'])
def keygen():
    rsa = RSA()
    k = rsa.keygen(bits=256)
    keys['sk'] = k
    keys['vk'] = {"N": k["N"], "e": k["e"]}
    return jsonify({"success": True, "vk": keys['vk']})

@pa15.route('/sign', methods=['POST'])
def sign_demo():
    data = request.get_json() or {}
    message = data.get('message', 'hello')
    raw = data.get('raw', False)
    
    if 'sk' not in keys:
        keygen()
        
    try:
        if raw:
            # Need to sign integer for raw demo
            m_int = int.from_bytes(message.encode(), 'big')
            sigma = sign_raw(keys['sk'], m_int)
        else:
            sigma = sign(keys['sk'], message)
        return jsonify({
            "success": True, 
            "signature": hex(sigma)[2:], 
            "vk": {"N": hex(keys['vk']["N"])[2:], "e": keys['vk']["e"]}
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@pa15.route('/verify', methods=['POST'])
def verify_demo():
    data = request.get_json() or {}
    message = data.get('message', 'hello')
    sigma = data.get('signature', 0)
    raw = data.get('raw', False)
    tampered = data.get('tampered', False)
    
    if tampered:
        if raw:
            # message is int, flip bottom bit
            message = message ^ 1
        else:
            # message is str, flip bottom bit of first char
            if len(message) > 0:
                message = chr(ord(message[0]) ^ 1) + message[1:]
    
    if 'vk' not in keys:
        return jsonify({"success": False, "error": "No keys generated"})
        
    try:
        sigma = int(str(sigma), 16)
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Invalid signature format"})
        
    try:
        if raw:
            m_int = int(message) if isinstance(message, str) else message
            res = verify_raw_with_intermediates(keys['vk'], m_int, sigma)
        else:
            res = verify_with_intermediates(keys['vk'], message, sigma)
            
        return jsonify({
            "success": True, 
            "valid": res["valid"],
            "h_m": hex(res["h_m"])[2:],
            "sigma_e": hex(res["sigma_e"])[2:],
            "message": message
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@pa15.route('/forge', methods=['POST'])
def forge_demo():
    data = request.get_json() or {}
    m1 = data.get('m1', 2)
    m2 = data.get('m2', 3)
    
    if 'sk' not in keys:
        keygen()
        
    s1 = sign_raw(keys['sk'], m1)
    s2 = sign_raw(keys['sk'], m2)
    
    # Forged signature for m1*m2
    s_forged = (s1 * s2) % keys['sk']['N']
    m_forged = (m1 * m2) % keys['sk']['N']
    
    is_valid = verify_raw(keys['vk'], m_forged, s_forged)
    
    return jsonify({
        "success": True, 
        "m1": m1, "s1": hex(s1)[2:],
        "m2": m2, "s2": hex(s2)[2:],
        "m_forged": m_forged,
        "s_forged": hex(s_forged)[2:],
        "valid": is_valid
    })

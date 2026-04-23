"""
backend/app.py
==============
Flask application entrypoint for the POIS Cryptographic Primitives API.

Blueprint registration
----------------------
pa1  — OWF + PRG          (routes in PA1/app_pa1.py)
pa2  — GGM PRF + AES PRF  (routes in PA2/app_pa2.py)
pa3  — CPA Encryption     (routes in PA3/app_pa3.py)
pa4  — Modes of Operation (routes in PA4/app_pa4.py)

Future blueprints (PA#5–PA#8) will be registered below as implemented.
"""

from flask import Flask
from flask_cors import CORS
import os
import sys

_BASE = os.path.dirname(os.path.abspath(__file__))

# Register all PA directories + shared on sys.path so blueprints can import
# their own modules with bare names (e.g. `from owf import DLP_OWF`).
for _sub in ["shared", "PA1", "PA2", "PA3", "PA4", "PA5", "PA6"]:
    _p = os.path.join(_BASE, _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Also put the backend root on the path (needed by distinguisher.py)
if _BASE not in sys.path:
    sys.path.insert(0, _BASE)

from PA1.app_pa1 import pa1
from PA2.app_pa2 import pa2
from PA3.app_pa3 import pa3
from PA4.app_pa4 import pa4
from PA5.app_pa5 import pa5
from PA6.app_pa6 import pa6

app = Flask(__name__)
CORS(app)

app.register_blueprint(pa1)
app.register_blueprint(pa2)
app.register_blueprint(pa3)
app.register_blueprint(pa4)
app.register_blueprint(pa5)
app.register_blueprint(pa6)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
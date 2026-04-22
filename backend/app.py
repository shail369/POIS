from flask import Flask
from flask_cors import CORS
import sys
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, os.path.join(BASE_DIR, "PA1"))
sys.path.insert(0, os.path.join(BASE_DIR, "PA2"))
sys.path.insert(0, os.path.join(BASE_DIR, "PA3"))
sys.path.insert(0, os.path.join(BASE_DIR, "PA4"))

from app_pa1 import pa1
from app_pa2 import pa2
from app_pa3 import pa3
from app_pa4 import pa4

app = Flask(__name__)
CORS(app)

app.register_blueprint(pa1)
app.register_blueprint(pa2)
app.register_blueprint(pa3)
app.register_blueprint(pa4)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
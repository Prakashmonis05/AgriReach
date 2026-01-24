from flask import Flask, render_template
from extensions import bcrypt
from models import db, User, ChatMemory, Scheme ,Admin  # Import models BEFORE create_all()
import os
from datetime import datetime
from admin import admin_bp
from routes.auth_routes import auth
from routes.dashboard_routes import dashboard
from routes.weather_routes import weather
from routes.chatbot_routes import chatbot
from routes.schemes_routes import schemes
from routes.contact_routes import contact

from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, 'instance')
DB_PATH = os.path.join(INSTANCE_DIR, 'agrireach.db')

os.makedirs(INSTANCE_DIR, exist_ok=True)

app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{DB_PATH}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["SECRET_KEY"] = 'prakash'

db.init_app(app)
bcrypt.init_app(app)

with app.app_context():
    db.create_all()
    print("📦 Database initialized at:", DB_PATH)


@app.route('/')
def index():
    return render_template('index.html')

@app.route("/health")
def health():
    return "OK", 200

@app.template_filter("datetimeformat")
def datetimeformat(value):
    return datetime.fromtimestamp(value).strftime("%d %b %Y")

app.register_blueprint(auth)
app.register_blueprint(dashboard)
app.register_blueprint(weather)
app.register_blueprint(chatbot)
app.register_blueprint(schemes)
app.register_blueprint(contact)
app.register_blueprint(admin_bp)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
from flask import Flask, render_template
from flask_bcrypt import Bcrypt
from models import db, User, ChatMemory, Scheme   # Import models BEFORE create_all()
import os
from datetime import datetime
from admin import admin_bp



# BLUEPRINT IMPORTS
from routes.auth_routes import auth
from routes.dashboard_routes import dashboard
from routes.weather_routes import weather
from routes.chatbot_routes import chatbot
from routes.schemes_routes import schemes
from routes.contact_routes import contact


# -------------------------------
# Flask initializationmnbmn
# -------------------------------
app = Flask(__name__)

# -------------------------------
# Build Absolute Database Path
# -------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, 'instance')
DB_PATH = os.path.join(INSTANCE_DIR, 'agrireach.db')

# Ensure instance folder exists
os.makedirs(INSTANCE_DIR, exist_ok=True)

# -------------------------------
# App Configuration
# -------------------------------
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{DB_PATH}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = "your_secret_key"

# Initialize Extensions
db.init_app(app)
bcrypt = Bcrypt(app)

# -------------------------------
# Database Initialization
# -------------------------------
with app.app_context():
    db.create_all()
    print("📦 Database initialized at:", DB_PATH)


# -------------------------------
# Index Route
# -------------------------------
@app.route('/')
def index():
    return render_template('index.html')


# -------------------------------
# Global Template Filters
# -------------------------------
@app.template_filter("datetimeformat")
def datetimeformat(value):
    return datetime.fromtimestamp(value).strftime("%d %b %Y")


# -------------------------------
# Register Blueprints
# -------------------------------
app.register_blueprint(auth)
app.register_blueprint(dashboard)
app.register_blueprint(weather)
app.register_blueprint(chatbot)
app.register_blueprint(schemes)
app.register_blueprint(contact)
app.register_blueprint(admin_bp)





# -------------------------------
# Run Server
# -------------------------------
if __name__ == "__main__":
    app.run(debug=True)

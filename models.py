from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    password = db.Column(db.String(255), nullable=False)

class ChatMemory(db.Model):
    __tablename__ = "chat_memory"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(50))
    role = db.Column(db.String(10))  # 'user' or 'assistant'
    message = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class Scheme(db.Model):
    __tablename__ = "scheme"

    # ---- Primary Identifiers ----
    id = db.Column(db.Integer, primary_key=True)
    scheme_id = db.Column(db.String(50), unique=True, nullable=False)  
    # e.g. satgmsa (from URL)

    name = db.Column(db.String(255), nullable=False)
    scheme_url = db.Column(db.String(500), nullable=False)

    # ---- Coverage & Classification ----
    state = db.Column(db.String(100), nullable=True)        # Nagaland
    coverage_type = db.Column(db.String(50), nullable=True) # State / Central
    category = db.Column(db.String(100), nullable=True)     # Agriculture

    tags = db.Column(db.Text, nullable=True)  
    # stored as comma-separated: "Agriculture,MSc,Student,Thesis Grant"

    scheme_type = db.Column(db.String(100), nullable=True)  
    # Grant / Subsidy / Scholarship (derived)

    beneficiary_type = db.Column(db.String(100), nullable=True)  
    # Farmer / Student / Citizen

    # ---- Description (From Card) ----
    description = db.Column(db.Text, nullable=True)

    # ---- Detail Page Data (Filled Later) ----
    ministry = db.Column(db.String(255), nullable=True)
    launch_year = db.Column(db.Integer, nullable=True)
    objective = db.Column(db.Text, nullable=True)
    benefit = db.Column(db.Text, nullable=True)
    eligibility = db.Column(db.Text, nullable=True)

    # ---- Scraping Control ----
    source = db.Column(db.String(100), default="myScheme")
    content_hash = db.Column(db.String(64), nullable=True)
    last_scraped = db.Column(db.DateTime, nullable=True)
    scrape_status = db.Column(db.String(50), default="pending")

    # ---- Audit ----
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )


class ChatMessage(db.Model):
    __tablename__ = "chat_message"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(255), nullable=False)  # email or phone or user_id
    sender = db.Column(db.String(50), nullable=False)    # "user" or "admin"
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)



class UserActivity(db.Model):
    __tablename__ = "user_activity"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(50), nullable=False)
    event_type = db.Column(db.String(30), nullable=False)  
    # login | signup | ai_usage
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


def log_activity(user_id, event_type):
    __tablename__ = "user_activity"
    entry = UserActivity(user_id=user_id, event_type=event_type)
    db.session.add(entry)
    db.session.commit()


class Admin(db.Model):
    __tablename__ = "admins"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
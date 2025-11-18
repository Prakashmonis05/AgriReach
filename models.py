from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    password = db.Column(db.String(255), nullable=False)

class ChatMemory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(50))
    role = db.Column(db.String(10))  # 'user' or 'assistant'
    message = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class Scheme(db.Model):
    __tablename__ = "scheme" 
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    launch_year = db.Column(db.Integer, nullable=False)
    ministry = db.Column(db.String(255), nullable=False)
    type = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    objective = db.Column(db.Text, nullable=False)
    benefit = db.Column(db.Text, nullable=False)
    eligibility = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)

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
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(50), nullable=False)
    event_type = db.Column(db.String(30), nullable=False)  
    # login | signup | ai_usage
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


def log_activity(user_id, event_type):
    entry = UserActivity(user_id=user_id, event_type=event_type)
    db.session.add(entry)
    db.session.commit()

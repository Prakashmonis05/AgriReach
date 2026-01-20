from flask import render_template, request, redirect, url_for, session, flash, jsonify
from . import admin_bp
from models import User, Scheme, ChatMemory, db, ChatMessage, UserActivity, Admin
from functools import wraps
from datetime import datetime, timedelta
from sqlalchemy import func, distinct

# ========= Protect Routes =========
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin.admin_login"))
        return f(*args, **kwargs)
    return wrapper

@admin_bp.route("/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        admin = Admin.query.filter_by(username=username).first()

        if admin and admin.check_password(password):
            session["admin_logged_in"] = True
            session["admin_id"] = admin.id
            return redirect(url_for("admin.admin_dashboard"))
        else:
            flash("Invalid username or password", "danger")

    return render_template("admin/login.html")

# ========= Admin Logout =========
@admin_bp.route("/logout")
@admin_required
def admin_logout():
    session.pop("admin_logged_in", None)
    session.pop("admin_id", None)
    return redirect(url_for("admin.admin_login"))

# ========= Dashboard =========
@admin_bp.route("/dashboard")
@admin_required
def admin_dashboard():
    users = User.query.all()   # Fetch all users
    user_count = len(users)
    return render_template("admin/dashboard.html", users=users,user_count=user_count)


@admin_bp.route("/schemes")
@admin_required
def admin_schemes():
    # clear old flash messages
    session.pop('_flashes', None)

    # always show latest schemes (after refresh)
    schemes = Scheme.query.order_by(Scheme.created_at.desc()).all()

    return render_template(
        "admin/schemes.html",
        schemes=schemes
    )



@admin_bp.route("/schemes/edit/<int:id>", methods=["GET", "POST"])
@admin_required
def admin_edit_scheme(id):
    scheme = Scheme.query.get_or_404(id)

    if request.method == "POST":
        scheme.name = request.form.get("name")
        scheme.state = request.form.get("state")
        scheme.category = request.form.get("category")
        scheme.description = request.form.get("description")
        scheme.source = request.form.get("source")
        scheme.scheme_url = request.form.get("scheme_url")
        db.session.commit()
        flash("Scheme updated successfully!", "success")
        return redirect(url_for("admin.admin_schemes"))

    return render_template("admin/schemes_edit.html", scheme=scheme)



@admin_bp.route("/schemes/delete/<int:id>")
@admin_required
def admin_delete_scheme(id):
    scheme = Scheme.query.get_or_404(id)

    db.session.delete(scheme)
    db.session.commit()

    flash("Scheme deleted successfully!", "success")
    return redirect(url_for("admin.admin_schemes"))

@admin_bp.route("/")
def admin_root():
    return redirect(url_for("admin.admin_login"))


@admin_bp.route("/messages", defaults={"user_id": None})
@admin_bp.route("/messages/<user_id>")
@admin_required
def admin_messages(user_id):

    # Get distinct user_ids from chat table
    distinct_ids = db.session.query(ChatMessage.user_id).distinct().all()

    # Convert IDs → names
    users = []
    for uid in distinct_ids:
        u = User.query.get(uid[0])
        users.append({
            "id": uid[0],
            "name": u.name if u else f"User {uid[0]}"
        })

    # If no user selected yet → auto load first user
    if user_id is None:
        if len(users) > 0:
            user_id = users[0]["id"]
        else:
            return render_template("admin/messages.html", users=[], messages=[])

    # Fetch selected user's name
    current_user = User.query.get(user_id)
    user_name = current_user.name if current_user else f"User {user_id}"

    # Fetch messages of selected user
    messages = ChatMessage.query.filter_by(user_id=user_id)\
                                .order_by(ChatMessage.created_at)\
                                .all()

    # Render single page = messages.html
    return render_template(
        "admin/messages.html",
        users=users,
        messages=messages,
        user_id=user_id,
        user_name=user_name
    )



from services.scheme_scraper import run_scheme_scraper

@admin_bp.route("/schemes/refresh")
@admin_required
def refresh_schemes():
    try:
        # delete old data
        db.session.query(Scheme).delete()
        db.session.commit()

        # scrape fresh data
        run_scheme_scraper()

        flash("Schemes refreshed successfully.", "success")

    except Exception as e:
        db.session.rollback()
        flash(f"Refresh failed: {e}", "danger")

    return redirect(url_for("admin.admin_schemes"))



@admin_bp.route("/messages/<user_id>/send", methods=["POST"])
@admin_required
def admin_send_message(user_id):
    msg = request.form.get("message")

    new_msg = ChatMessage(
        user_id=user_id,
        sender="admin",
        message=msg
    )

    db.session.add(new_msg)
    db.session.commit()

    return redirect(url_for("admin.admin_messages", user_id=user_id))




def count_unique_users(event_type, days):
    cutoff = datetime.utcnow() - timedelta(days=days)
    return db.session.query(func.count(distinct(UserActivity.user_id))) \
        .filter(UserActivity.event_type == event_type) \
        .filter(UserActivity.timestamp >= cutoff) \
        .scalar()


# Daily, Weekly, Monthly Active Users (Unique)
def get_dau():
    return count_unique_users("login", 1)

def get_wau():
    return count_unique_users("login", 7)

def get_mau():
    return count_unique_users("login", 30)


# ----------- NEW USER SIGNUPS (UNIQUE) -----------

def new_users(days):
    return count_unique_users("signup", days)


# ----------- AI USAGE (UNIQUE & TOTAL) -----------

# Unique users who used AI
def ai_active_users(days):
    return count_unique_users("ai_usage", days)

# Total AI messages (NOT unique — this is correct)
def ai_message_count(days):
    cutoff = datetime.utcnow() - timedelta(days=days)
    return UserActivity.query \
        .filter(UserActivity.event_type == "ai_usage") \
        .filter(UserActivity.timestamp >= cutoff) \
        .count()

# Single unified analytics API endpoint
@admin_bp.route("/api/analytics")
def analytics_data():
    return jsonify({
        "dau": get_dau(),
        "wau": get_wau(),
        "mau": get_mau(),

        "new_users_today": new_users(1),
        "new_users_month": new_users(30),

        "ai_users_today": ai_active_users(1),
        "ai_users_month": ai_active_users(30),

        "ai_messages_today": ai_message_count(1),
        "ai_messages_month": ai_message_count(30)
    })
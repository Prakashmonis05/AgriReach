from flask import render_template, request, redirect, url_for, session, flash, jsonify
from . import admin_bp
from models import User, Scheme, ChatMemory, db, ChatMessage, UserActivity
from functools import wraps
from datetime import datetime, timedelta


# ========= Default Admin Credentials =========
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"


# ========= Protect Routes =========
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin.admin_login"))
        return f(*args, **kwargs)
    return wrapper


# ========= Admin Login =========
@admin_bp.route("/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["admin_logged_in"] = True
            return redirect(url_for("admin.admin_dashboard"))
        else:
            flash("Invalid username or password", "danger")

    return render_template("admin/login.html")


# ========= Admin Logout =========
@admin_bp.route("/logout")
def admin_logout():
    session.pop("admin_logged_in", None)
    return redirect(url_for("admin.admin_login"))


# ========= Dashboard =========
@admin_bp.route("/dashboard")
@admin_required
def admin_dashboard():
    users = User.query.all()
    return render_template("admin/dashboard.html", users=users)



@admin_bp.route("/schemes")
@admin_required
def admin_schemes():
    schemes = Scheme.query.all()
    return render_template("admin/schemes.html", schemes=schemes)
@admin_bp.route("/schemes/create", methods=["GET", "POST"])
@admin_required
def admin_create_scheme():
    if request.method == "POST":

        new_scheme = Scheme(
            name=request.form.get("name"),
            launch_year=request.form.get("launch_year"),
            ministry=request.form.get("ministry"),
            type=request.form.get("type"),
            status=request.form.get("status"),
            objective=request.form.get("objective"),
            benefit=request.form.get("benefit"),
            eligibility=request.form.get("eligibility"),
            category=request.form.get("category")
        )

        db.session.add(new_scheme)
        db.session.commit()

        flash("Scheme created successfully!", "success")
        return redirect(url_for("admin.admin_schemes"))

    return render_template("admin/schemes_create.html")

@admin_bp.route("/schemes/edit/<int:id>", methods=["GET", "POST"])
@admin_required
def admin_edit_scheme(id):
    scheme = Scheme.query.get_or_404(id)

    if request.method == "POST":

        scheme.name = request.form.get("name")
        scheme.launch_year = request.form.get("launch_year")
        scheme.ministry = request.form.get("ministry")
        scheme.type = request.form.get("type")
        scheme.status = request.form.get("status")
        scheme.objective = request.form.get("objective")
        scheme.benefit = request.form.get("benefit")
        scheme.eligibility = request.form.get("eligibility")
        scheme.category = request.form.get("category")

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




# Generic active user counter for login events
def count_active_users(days):
    cutoff = datetime.utcnow() - timedelta(days=days)
    return UserActivity.query \
        .filter(UserActivity.event_type == "login") \
        .filter(UserActivity.timestamp >= cutoff) \
        .distinct(UserActivity.user_id).count()


# Daily Active Users
def get_dau():
    return count_active_users(1)


# Weekly Active Users
def get_wau():
    return count_active_users(7)


# Monthly Active Users
def get_mau():
    return count_active_users(30)


# New user signups
def new_users(days):
    cutoff = datetime.utcnow() - timedelta(days=days)
    return UserActivity.query \
        .filter(UserActivity.event_type == "signup") \
        .filter(UserActivity.timestamp >= cutoff).count()


# AI usage – unique users
def ai_active_users(days):
    cutoff = datetime.utcnow() - timedelta(days=days)
    return UserActivity.query \
        .filter(UserActivity.event_type == "ai_usage") \
        .filter(UserActivity.timestamp >= cutoff) \
        .distinct(UserActivity.user_id).count()


# AI usage – total messages
def ai_message_count(days):
    cutoff = datetime.utcnow() - timedelta(days=days)
    return UserActivity.query \
        .filter(UserActivity.event_type == "ai_usage") \
        .filter(UserActivity.timestamp >= cutoff).count()


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
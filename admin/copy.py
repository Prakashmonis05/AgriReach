from flask import render_template, request, redirect, url_for, session, flash
from . import admin_bp
from models import User, Scheme, ChatMemory, db
from functools import wraps


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

@admin_bp.route('/admin')
def admin_root():
    return redirect(url_for('admin.admin_login'))



@admin_bp.route("/schemes")
@admin_required
def admin_schemes():
    schemes = Scheme.query.all()
    return render_template("admin/schemes.html", schemes=schemes)

@admin_bp.route("/schemes/create", methods=["GET", "POST"])
@admin_required
def admin_create_scheme():
    if request.method == "POST":
        title = request.form.get("title")
        description = request.form.get("description")
        benefits = request.form.get("benefits")

        new_scheme = Scheme(title=title, description=description, benefits=benefits)
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
        scheme.title = request.form.get("title")
        scheme.description = request.form.get("description")
        scheme.benefits = request.form.get("benefits")

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

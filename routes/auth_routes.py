from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from models import db, User, log_activity
from flask_bcrypt import Bcrypt
from extensions import bcrypt


auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        # Backend Validation
        if not email or not password:
            flash('All fields are required.', 'danger')
            return redirect(url_for('auth.login'))

        if '@' not in email or '.' not in email:
            flash('Invalid email format.', 'danger')
            return redirect(url_for('auth.login'))

        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return redirect(url_for('auth.login'))

        user = User.query.filter_by(email=email).first()

        if not user:
            # ❌ Email not found
            flash('Email not found.', 'danger')
            return redirect(url_for('auth.login'))

        if not bcrypt.check_password_hash(user.password, password):
            # ❌ Incorrect password
            flash('Incorrect password.', 'danger')
            return redirect(url_for('auth.login'))

        # 🟩 Correct login
        log_activity(user.id, "login")
        session['user_id'] = user.id
        session['user_name'] = user.name
        flash('Login successful!', 'success')
        return redirect(url_for('dashboard.dashboard_page'))

    return render_template('login.html')


@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip().lower()
        phone = request.form['phone'].strip()
        password = request.form['password']
        confirm = request.form['confirm']

        # Basic checks
        if password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('auth.register'))

        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "warning")
            return redirect(url_for('auth.register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(name=name, email=email, phone=phone, password=hashed_password)
        db.session.add(user)
        db.session.commit()

        # 🟦 **Log activity: SIGNUP**
        log_activity(user.id, "signup")

        flash("Account created successfully. Please log in.", "success")
        return redirect(url_for('auth.login'))

    return render_template('register.html')




@auth.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", 'info')
    return redirect(url_for('index'))

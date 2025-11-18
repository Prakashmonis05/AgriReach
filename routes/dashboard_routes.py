from flask import Blueprint, render_template, session, redirect, url_for, flash

dashboard = Blueprint('dashboard', __name__)


@dashboard.route('/dashboard')
def dashboard_page():
    if 'user_id' not in session:
        flash("Please log in first.", 'warning')
        return redirect(url_for('auth.login'))
    return render_template('dashboard.html', user_name=session['user_name'])

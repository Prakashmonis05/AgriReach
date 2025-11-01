from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_bcrypt import Bcrypt
from models import db, User
import os

app = Flask(__name__)

# --- Build Absolute Database Path ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, 'instance')
DB_PATH = os.path.join(INSTANCE_DIR, 'agrireach.db')

# --- Ensure instance directory exists ---
os.makedirs(INSTANCE_DIR, exist_ok=True)

# --- App Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key'

# --- Initialize Extensions ---
db.init_app(app)
bcrypt = Bcrypt(app)

# --- Create DB Tables if Not Exist ---
with app.app_context():
    db.create_all()
    print(f"✅ Database ready at: {DB_PATH}")
  
# --- Routes ---
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        # Backend Validation
        if not email or not password:
            flash('All fields are required.', 'danger')
            return redirect(url_for('login'))

        if '@' not in email or '.' not in email:
            flash('Invalid email format.', 'danger')
            return redirect(url_for('login'))

        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return redirect(url_for('login'))

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_name'] = user.name
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')



@app.route('/register', methods=['GET', 'POST'])
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
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "warning")
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(name=name, email=email, phone=phone, password=hashed_password)
        db.session.add(user)
        db.session.commit()

        flash("Account created successfully. Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')



@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please log in first.", 'warning')
        return redirect(url_for('login'))
    return render_template('dashboard.html', user_name=session['user_name'])


# --- Dummy Routes ---

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/weather')
def weather():
    return render_template('weather.html')

@app.route('/schemes')
def schemes():
    return render_template('schemes.html')

@app.route('/chatbot')
def chatbot_page():
    return render_template('chatbot.html')



@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", 'info')
    return redirect(url_for('index'))


# --- Initialize Database ---
if __name__ == '__main__':
    app.run(debug=True)

import os
import re
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime

# ---------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------
app = Flask(__name__)
app.secret_key = 'verysecretkey'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tq_pictures.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)

# ---------------------------------------------------
# MODELS
# ---------------------------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    ratings = db.relationship('Rating', backref='user', lazy=True)
    appointments = db.relationship('Appointment', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    caption = db.Column(db.String(200))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    ratings = db.relationship('Rating', backref='image', lazy=True)


class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    image_id = db.Column(db.Integer, db.ForeignKey('image.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)


class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    reason = db.Column(db.String(200), nullable=False)
    datetime = db.Column(db.String(100), nullable=False)


# ---------------------------------------------------
# VALIDATION HELPERS
# ---------------------------------------------------
def allowed_file(filename):
    return (
        '.' in filename
        and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def validate_email(email):
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}$'
    return bool(re.match(regex, email))


def validate_phone_number(phone):
    # South African numbers: 0XXXXXXXXX or +27XXXXXXXXX
    regex = r'^(0\d{9}|(\+27)\d{9})$'
    return bool(re.match(regex, phone))


def validate_password(password):
    # MUST include lowercase, uppercase, number and be 8 chars minimum
    regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$'
    return bool(re.match(regex, password))


# ---------------------------------------------------
# ROUTES
# ---------------------------------------------------

user = User.query.get(session['user_id'])
if not user:
    session.pop('user_id', None)
    flash('User not found. Please login again.')
    return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    images = Image.query.filter(
        (Image.user_id == user.id) | (Image.user_id == None)
    ).all()

    user_ratings = {r.image_id: r.score for r in user.ratings}

    frame_sizes = [
        {"size": "4x6", "description": "Small, perfect for albums"},
        {"size": "8x10", "description": "Classic portrait size"},
        {"size": "12x16", "description": "Ideal for wall display"},
    ]

    return render_template(
        'main.html',
        user=user,
        images=images,
        user_ratings=user_ratings,
        frame_sizes=frame_sizes
    )


# ---------------------------------------------------
# SIGNUP
# ---------------------------------------------------
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        password = request.form.get('password')

        # VALIDATIONS
        if not full_name or len(full_name) < 3:
            flash("Full name must be at least 3 characters.")
            return redirect(url_for('signup'))

        if not validate_email(email):
            flash("Invalid email address.")
            return redirect(url_for('signup'))

        if not validate_phone_number(phone_number):
            flash("Invalid South African phone number format.")
            return redirect(url_for('signup'))

        if not validate_password(password):
            flash("Password must contain uppercase, lowercase, a number, and be 8+ characters.")
            return redirect(url_for('signup'))

        if User.query.filter_by(email=email).first():
            flash("This email is already registered.")
            return redirect(url_for('signup'))

        user = User(full_name=full_name, email=email, phone_number=phone_number)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Signup successful! Please login.")
        return redirect(url_for('login'))

    return render_template('signup.html')


# ---------------------------------------------------
# LOGIN
# ---------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            flash("Login successful!")
            return redirect(url_for('main_page'))

        flash("Invalid email or password.")
        return redirect(url_for('login'))

    return render_template('login.html')


# ---------------------------------------------------
# LOGOUT
# ---------------------------------------------------
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("Logged out.")
    return redirect(url_for('login'))


# ---------------------------------------------------
# ADMIN LOGIN
# ---------------------------------------------------
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        admin = Admin.query.filter_by(username=username).first()

        if admin and admin.check_password(password):
            session['admin_id'] = admin.id
            return redirect(url_for('admin_dashboard'))

        flash("Invalid admin credentials.")
        return redirect(url_for('admin_login'))

    return render_template('admin_login.html')


# ---------------------------------------------------
# ADMIN DASHBOARD
# ---------------------------------------------------
@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'admin_id' not in session:
        flash("Please login as admin.")
        return redirect(url_for('admin_login'))

    users = User.query.all()
    images = Image.query.all()

    if request.method == 'POST':
        file = request.files.get('image_file')
        caption = request.form.get('caption')
        user_id = request.form.get('user_id')

        if not file or not allowed_file(file.filename):
            flash("Invalid file format.")
            return redirect(url_for('admin_dashboard'))

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        if user_id == "none":
            user_id = None

        new_image = Image(filename=filename, caption=caption, user_id=user_id)
        db.session.add(new_image)
        db.session.commit()

        flash("Image uploaded successfully.")
        return redirect(url_for('admin_dashboard'))

    return render_template('admin_dashboard.html', users=users, images=images)


# ---------------------------------------------------
# RATE IMAGE
# ---------------------------------------------------
@app.route('/rate_image/<int:image_id>', methods=['POST'])
def rate_image(image_id):
    if 'user_id' not in session:
        flash("Please login.")
        return redirect(url_for('login'))

    score = int(request.form.get("score", 0))
    if score < 1 or score > 5:
        flash("Invalid rating score.")
        return redirect(url_for('main_page'))

    rating = Rating.query.filter_by(
        user_id=session['user_id'], image_id=image_id
    ).first()

    if rating:
        rating.score = score
    else:
        rating = Rating(
            user_id=session['user_id'], image_id=image_id, score=score
        )
        db.session.add(rating)

    db.session.commit()

    flash("Rating submitted.")
    return redirect(url_for('main_page'))


# ---------------------------------------------------
# APPOINTMENTS
# ---------------------------------------------------
@app.route('/appointment', methods=['POST'])
def appointment():
    if 'user_id' not in session:
        flash("Please login.")
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    phone = request.form.get('phone_number')
    email = request.form.get('email')
    reason = request.form.get('reason')
    date_str = request.form.get('date')
    time_str = request.form.get('time')

    if not validate_phone_number(phone):
        flash("Invalid phone number.")
        return redirect(url_for('main_page'))

    if not validate_email(email):
        flash("Invalid email.")
        return redirect(url_for('main_page'))

    if not reason:
        flash("Reason is required.")
        return redirect(url_for('main_page'))

    # Date + time combined validation
    try:
        dt = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M")
    except:
        flash("Invalid date or time format.")
        return redirect(url_for('main_page'))

    appointment = Appointment(
        user_id=user.id,
        phone_number=phone,
        email=email,
        reason=reason,
        datetime=f"{date_str} {time_str}"
    )
    db.session.add(appointment)
    db.session.commit()

    flash("Appointment booked successfully.")
    return redirect(url_for('main_page'))


# ---------------------------------------------------
# INITIAL SETUP
# ---------------------------------------------------
def initialize_app():
    with app.app_context():
        db.create_all()

        # Create default admin if not exists
        if not Admin.query.filter_by(username="admin").first():
            admin = Admin(username="admin")
            admin.set_password("TyraMokhotla2705")  # CHANGE IN PRODUCTION
            db.session.add(admin)
            db.session.commit()


initialize_app()


# ---------------------------------------------------
# RUN
# ---------------------------------------------------
if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

    app.run(debug=True)

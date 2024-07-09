import html
import logging
import re

from flask import Flask, render_template, request, session, redirect, url_for, flash, current_app, jsonify
from flask_mail import Mail, Message
from Forms import CreateUserForm, UpdateProfileForm, LoginForm, AdminLoginForm, CreateVehicleForm
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv, find_dotenv
from datetime import datetime, timedelta, timezone
from functools import wraps
import hashlib
import hmac
import os
import model
import random
import string
import secrets
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exists

from model import *

load_dotenv(find_dotenv())
db = SQLAlchemy()

app = Flask(__name__)

logging.basicConfig(filename='app.log', level=logging.DEBUG,
                    format=f'%(asctime)s %(levelname)s: %(message)s')


app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URI")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=20)  # Session timeout after 30 minutes

app.config.update(
    SESSION_COOKIE_SECURE=True,  # Only send cookie over HTTPS
    SESSION_COOKIE_HTTPONLY=True,  # Prevent JavaScript access to cookies
    SESSION_COOKIE_SAMESITE='Lax',  # Helps mitigate CSRF
)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASS')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('EMAIL_USER')
mail = Mail(app)
otp_store = {}

user_logged_in = False

with app.app_context():
    db.init_app(app)
    db.create_all()  # Create sql tables


@app.route('/')
def home():
    token = request.args.get('token')
    stored_token = session.get('token')

    if token != stored_token:
        return "Sorry, an unexpected error occurred. :("
    return render_template("homepage/homepage.html", token=token)


@app.route('/models')
def models():
    return render_template("homepage/models.html")


@app.route('/check_session')
def check_session():
    # Log the current state of the session for debugging
    app.logger.info("Session data: %s", session)

    if 'expiry_time' in session:
        current_time = datetime.now(timezone.utc).timestamp()
        expiry_time = session['expiry_time']

        app.logger.info("Current time: %s", current_time)
        app.logger.info("Session expiry time: %s", expiry_time)

        if current_time > expiry_time:
            app.logger.info("Session expired: True")
            session.clear()
            session.modified = True
            return jsonify(expired=True), 200

    app.logger.info("Session expired: False")
    return jsonify(expired=False), 200


@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    error = None
    create_user_form = CreateUserForm(request.form)
    if request.method == 'POST' and create_user_form.validate():
        # Extract data from form submission
        full_name = create_user_form.full_name.data
        username = create_user_form.username.data
        email = create_user_form.email.data
        phone_number = create_user_form.phone_number.data
        password = create_user_form.password.data
        confirm_password = create_user_form.confirm_password.data

        # Check if the user already exists
        user_exists = db.session.query(exists().where(User.username == username)).scalar()
        email_exists = db.session.query(exists().where(User.email == email)).scalar()
        phone_number_exists = db.session.query(exists().where(User.phone_number == phone_number)).scalar()

        if user_exists:
            error = "Username already exists!"
        elif email_exists:
            error = "Email is already registered!"
        elif phone_number_exists:
            error = "Phone number is already registered!"
        elif password != confirm_password:
            error = "Passwords do not match!"
        elif len(str(phone_number)) != 8:
            error = "Phone number must be 8 digits."
        else:
            # Validate special characters
            if any(char in "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?'" for char in full_name):
                error = "Special characters are not allowed in the full name."

        if error is None:
            hashed_password = generate_password_hash(password)
            new_user = User(full_name=full_name, username=username, email=email, phone_number=phone_number,
                            password_hash=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            app.logger.info(f"User {email} added to database.")
            return redirect(url_for('login'))
    return render_template("customer/sign_up.html", form=create_user_form, error=error)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_email' not in session:
            return redirect(url_for('login'))  # Redirect to login if user is not authenticated
        return f(*args, **kwargs)
    return decorated_function


def generate_user_id_hash(user_id):
    secret_key = current_app.config['SECRET_KEY']
    return hmac.new(secret_key.encode(), str(user_id).encode(), hashlib.sha256).hexdigest()


def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if session.get('user_logged_in'):
        return "You are already logged in."

    login_form = LoginForm(request.form)

    if request.method == 'POST' and login_form.validate():
        email = login_form.email.data
        password = login_form.password.data
        user = db.session.query(User).filter_by(email=email).first()

        if user:
            current_time = datetime.now(timezone.utc)

            if user.lockout_until and user.lockout_until > current_time:
                error = "Account is locked. Please try again later."
                app.logger.warning(f"Locked account login attempt for {email}")
            else:
                if user.lockout_until and user.lockout_until <= current_time:
                    user.failed_attempts = 0
                    user.lockout_until = None
                    db.session.commit()

                if check_password_hash(user.password_hash, password):
                    user.failed_attempts = 0
                    user.lockout_until = None
                    db.session.commit()

                    otp = generate_otp()
                    session.clear()  # Clear existing session data
                    session['otp'] = otp
                    session['user_email'] = email
                    session['user_logged_in'] = True

                    token = secrets.token_urlsafe(16)
                    session['token'] = token

                    send_otp_email(user.email, otp)
                    app.logger.info(f"OTP sent to {user.email}")

                    return redirect(url_for('verify_otp', token=token))
                else:
                    user.failed_attempts += 1

                    if user.failed_attempts >= 3:
                        user.lockout_until = current_time + timedelta(minutes=15)
                        error = "Too many failed attempts. Account is locked for 15 minutes."
                        app.logger.warning(f"Account locked for {email} after 3 failed attempts.")
                    else:
                        error = "Invalid email or password. Please try again."
                        app.logger.warning(f"Failed login attempt for {email}")

                    db.session.commit()
        else:
            error = "Invalid email or password. Please try again."
            app.logger.warning(f"Failed login attempt for {email}")

    return render_template("customer/login.html", form=login_form, error=error)


def send_otp_email(email, otp):
    msg = Message('Your OTP Code', recipients=[email])
    msg.body = f'Your OTP code is: {otp}'
    mail.send(msg)


def hide_email(email):
    parts = email.split('@')
    return parts[0][:2] + '****' + parts[0][-2:] + '@' + parts[1]


app.jinja_env.filters['hide_email'] = hide_email


@app.route('/verify_otp', methods=['GET', 'POST'])
@login_required
def verify_otp():
    error = None
    user_email = session.get('user_email')
    token = request.args.get('token')
    stored_token = session.get('token')

    user = db.session.query(User).filter_by(email=user_email).first()
    if not user:
        return redirect(url_for('login'))

    if request.method == 'POST':
        entered_otp_digits = [request.form.get(f'otp{i}') for i in range(1, 7)]
        entered_otp = ''.join(entered_otp_digits)
        otp = session.get('otp')

        if entered_otp == otp and stored_token == token:
            # Clear OTP from session
            session.pop('otp', None)
            session['user'] = user_email  # Set user in session
            session['expiry_time'] = (datetime.now(timezone.utc) + timedelta(minutes=20)).timestamp()
            session['user_logged_in'] = True
            session.permanent = True
            app.logger.info(f"User {user_email} logged in successfully.")
            return redirect(url_for('home', token=token))
        else:
            error = "Invalid OTP. Please try again."
            app.logger.warning(f"Invalid OTP attempt for {user_email}")

    return render_template('customer/verify_otp.html', error=error, user_email=user_email)


@app.route('/profile')
@login_required
def profile():
    user_email = session.get('user_email')
    token = request.args.get('token')
    stored_token = session.get('token')

    if token != stored_token:
        return "Sorry, an unexpected error occurred. :("

    if not user_email:
        return redirect(url_for('login'))  # Redirect to login if user email is not found in session

    user = db.session.query(User).filter_by(email=user_email).first()

    if not user:
        return redirect(url_for('login'))

    return render_template('customer/profile_page.html', user=user, token=token)


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    error = None
    user_email = session.get('user_email')
    token = request.args.get('token')
    stored_token = session.get('token')
    user = db.session.query(User).filter_by(email=user_email).first()

    if not user:
        return redirect(url_for('login'))  # Redirect to login if user not found in the database

    if token != stored_token:
        return "Sorry, an unexpected error occurred. :("

    edit_profile_form = UpdateProfileForm(request.form, obj=user)

    if request.method == 'POST' and edit_profile_form.validate():
        current_password = edit_profile_form.current_password.data
        new_password = edit_profile_form.new_password.data
        confirm_new_password = edit_profile_form.confirm_new_password.data

        # Verify current password
        if not check_password_hash(user.password_hash, current_password):
            error = 'Current password is incorrect.'
        elif new_password and new_password != confirm_new_password:
            error = 'New passwords do not match.'

        if error:
            return render_template('customer/edit_profile.html', user=user, form=edit_profile_form, token=token, error=error)

        # Update user details
        user.full_name = edit_profile_form.full_name.data
        user.username = edit_profile_form.username.data
        user.email = edit_profile_form.email.data
        user.phone_number = edit_profile_form.phone_number.data

        # Update password if new password is provided and matches confirmation
        if new_password == confirm_new_password:
            user.password_hash = generate_password_hash(new_password)

        db.session.commit()
        error = 'Profile updated successfully.'

    return render_template('customer/edit_profile.html', user=user, form=edit_profile_form, token=token, error=error)


@app.route('/user/logout')
def logout():
    if 'user_email' in session:
        user_email = session.pop('user_email', None)
        app.logger.info(f"User {user_email} logged out successfully.")
        session.clear()
        session.modified = True
        return redirect(url_for('home'))
    else:
        return "You are not logged in."


@app.before_request
def before_request():
    if 'user_email' in session:
        if 'expiry_time' in session and datetime.now(timezone.utc).timestamp() > session['expiry_time']:
            session.modified = True
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify(expired=True), 401  # Return JSON for the AJAX request


@app.route('/payment')
def payment():
    return render_template("customer/payment.html")


@app.route('/confirmation')
def confirmation():
    # Render a simple confirmation page
    return "Thank you for your order!"


@app.route('/process_payment', methods=['POST'])
def process_payment():
    try:
        fullname = request.form['firstname']
        email = request.form['email']
        address = request.form['address']
        city = request.form['city']
        state = request.form['state']
        zip_code = request.form['zip']
        card_name = request.form['cardname']
        card_number = request.form['cardnumber']
        exp_month = request.form['expmonth']
        exp_year = request.form['expyear']
        cvv = request.form['cvv']

        new_order = Order(fullname=fullname, email=email, address=address, city=city, state=state,
                          zip_code=zip_code, card_name=card_name, card_number=card_number,
                          exp_month=exp_month, exp_year=exp_year, cvv=cvv)
        db.session.add(new_order)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print("Failed to process payment:", e)  # Log the error or use a logging framework
        return "Error processing payment", 500
    return redirect(url_for('confirmation'))


# @app.route('/process_payment', methods=['POST'])
# def process_payment():
#     try:
#         fullname = request.form['firstname']
#         email = request.form['email']
#         address = request.form['address']
#         city = request.form['city']
#         state = request.form['state']
#         zip_code = request.form['zip']
#         card_name = request.form['cardname']
#         card_number = request.form['cardnumber']
#         exp_month = request.form['expmonth']
#         exp_year = request.form['expyear']
#         cvv = request.form['cvv']
#         cursor = db_2.cursor()
#         query = "INSERT INTO orders (fullname, email, address, city, state, zip_code, card_name, card_number, exp_month, exp_year, cvv) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
#         values = (fullname, email, address, city, state, zip_code, card_name, card_number, exp_month, exp_year, cvv)
#         cursor.execute(query, values)
#         db_2.commit()
#     except Exception as e:
#         db_2.session.rollback()
#         print("Failed to process payment:", e)  # Log the error or use a logging framework
#         return "Error processing payment", 500
#     return redirect(url_for('confirmation'))
#
# @app.route('/view_payment')
# def view_payment():
#     cursor = db_2.cursor(dictionary=True)
#     cursor.execute("SELECT * FROM orders")
#     orders = cursor.fetchall()
#     cursor.close()
#     return render_template("admin/view_payment.html", orders=orders)
#
#
# @app.route('/update_payment/<int:id>', methods=['GET', 'POST'])
# def update_payment(id):
#     if request.method == 'POST':
#         fullname = request.form['fullname']
#         email = request.form['email']
#         address = request.form['address']
#         city = request.form['city']
#         state = request.form['state']
#         zip_code = request.form['zip']
#         card_name = request.form['cardname']
#         card_number = request.form['cardnumber']
#         exp_month = request.form['expmonth']
#         exp_year = request.form['expyear']
#         cvv = request.form['cvv']
#
#         cursor = db_2.cursor()
#         cursor.execute("""
#             UPDATE orders SET fullname=%s, email=%s, address=%s, city=%s, state=%s, zip_code=%s, card_name=%s, card_number=%s, exp_month=%s, exp_year=%s, cvv=%s
#             WHERE order_id=%s
#         """, (fullname, email, address, city, state, zip_code, card_name, card_number, exp_month, exp_year, cvv, id))
#         db_2.commit()
#         cursor.close()
#         return redirect(url_for('view_payment'))
#     else:
#         cursor = db_2.cursor(dictionary=True)
#         cursor.execute("SELECT * FROM orders WHERE order_id = %s", (id,))
#         order = cursor.fetchone()
#         cursor.close()
#         return render_template('admin/update_payment.html', order=order)
#
# @app.route('/delete_payment/<int:id>', methods=['POST'])
# def delete_payment(id):
#     cursor = db_2.cursor()
#     cursor.execute("DELETE FROM orders WHERE order_id = %s", (id,))
#     db_2.commit()
#     cursor.close()
#     return redirect(url_for('view_payment'))


# NEED TO METHOD = 'POST' THESE ADMIN PAGES
@app.route('/admin_log_in', methods=['GET', 'POST'])
def admin_log_in():
    form = AdminLoginForm()
    if form.validate_on_submit():
        username = html.escape(form.username.data)  # Escape HTML characters
        password = html.escape(form.password.data)

        # Manually trigger field validation
        if not form.username.validate(form) or not form.password.validate(form):
            flash('Invalid characters in username or password', 'danger')
            return render_template('admin/admin_log_in.html', form=form)

        # Check for disallowed characters in username and password
        if not is_valid_input(username) or not is_valid_input(password):
            flash('Invalid characters in username or password', 'danger')
            return render_template('admin/admin_log_in.html', form=form)

        # Perform case-sensitive query for the admin with the given username
        admin = db.session.query(Admin).filter(func.binary(Admin.username) == username).first()

        # Compare the hashed input password with the hashed password in the database
        if admin and admin.check_password(password):
            session['admin_username'] = username  # Store the username in the session
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Error in {getattr(form, field).label.text}: {error}", 'danger')

    return render_template('admin/admin_log_in.html', form=form)

def is_valid_input(input_str):
    """
    Check if the input string contains only allowed characters.
    """
    # Define a regular expression to match allowed characters
    allowed_chars_pattern = re.compile(r'^[\w.@+-]+$')
    return bool(allowed_chars_pattern.match(input_str))

@app.route('/createVehicle', methods=['GET', 'POST'])
def createVehicle():
    form = CreateVehicleForm()
    if form.validate_on_submit():
        # Logic for form submission (e.g., saving data to the database)
        flash('Vehicle created successfully!', 'success')
        return redirect(url_for('dashboard'))  # Redirect to the 'dashboard' route upon successful form submission
    elif request.method == 'POST':
        # If it's a POST request but form validation fails, it means there are errors
        flash('There were errors in the form. Please correct them.', 'danger')
    return render_template('admin/createVehicleForm.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    admin_username = session.get('admin_username')
    return render_template('admin/dashboard.html', admin_username=admin_username)

@app.route('/manageCustomers')
def MCustomers():
    admin_username = session.get('admin_username')
    customers = db.session.query(User).all()  # Retrieve all users from the database
    return render_template('admin/manageCustomers.html', admin_username=admin_username, customers=customers)

@app.route('/manageVehicles')
def MVehicles():
    admin_username = session.get('admin_username')
    vehicles = db.session.query(Vehicle).all()
    return render_template('admin/manageVehicles.html', admin_username=admin_username, vehicles=vehicles)


@app.route('/delete_vehicle/<int:id>', methods=['POST'])
def delete_vehicle(id):
    # Retrieve the vehicle from the database
    vehicle = db.session.query(Vehicle).get(id)

    if vehicle:
        # Delete the vehicle from the database
        db.session.delete(vehicle)
        db.session.commit()
        flash('Vehicle deleted successfully!', 'success')
    else:
        flash('Vehicle not found!', 'danger')

    # Redirect back to the manageVehicles page
    return redirect(url_for('MVehicles'))

if __name__ == '__main__':
    app.run(debug=True)

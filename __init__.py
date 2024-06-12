import html
import logging
import re
from flask import Flask, render_template, request, session, redirect, url_for, flash, jsonify
from flask_mail import Mail, Message
from Forms import CreateUserForm, LoginForm, AdminLoginForm, CreateVehicleForm
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv, find_dotenv
from datetime import datetime, timedelta
from functools import wraps
import hashlib
import os
import model
import random
import string
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

with app.app_context():
    db.init_app(app)
    db.create_all()  # Create sql tables


@app.route('/')
def home():
    return render_template("homepage/homepage.html")


@app.route('/models')
def models():
    return render_template("homepage/models.html")


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


def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    login_form = LoginForm(request.form)
    if request.method == 'POST' and login_form.validate():
        email = login_form.email.data
        password = login_form.password.data
        user = db.session.query(User).filter_by(email=email).first()

        if user:
            current_time = datetime.utcnow()
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
                    session['otp'] = otp
                    session['user_email'] = email
                    send_otp_email(user.email, otp)
                    app.logger.info(f"OTP sent to {user.email}")
                    return redirect(url_for('verify_otp'))
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

    if request.method == 'POST':
        entered_otp_digits = [request.form.get(f'otp{i}') for i in range(1, 7)]
        print("Entered OTP digits:", entered_otp_digits)
        entered_otp = ''.join(entered_otp_digits)
        otp = session.get('otp')
        print("OTP from session:", otp)

        if entered_otp == otp:
            # Clear OTP from session
            session.pop('otp', None)

            if user_email:
                session['user'] = user_email  # Set user in session
                app.logger.info(f"User {user_email} logged in successfully.")
                return redirect(url_for('home'))
        else:
            error = "Invalid OTP. Please try again."

    return render_template('customer/verify_otp.html', error=error, user_email=user_email)


@app.route('/user/logout')
def logout():
    user_email = session.pop('user_email', None)
    if user_email:
        app.logger.info(f"User {user_email} logged out successfully.")
    session.clear()  # Clear all session data
    return redirect(url_for('home'))



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

        # Hash the input password using hashlib
        hashed_password_input = hashlib.sha256(password.encode()).hexdigest()

        admin = db.session.query(Admin).filter_by(username=username).first()

        # Compare the hashed input password with the hashed password in the database
        if admin and admin.password_hash == hashed_password_input:
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
    return render_template('admin/manageCustomers.html', admin_username=admin_username)


@app.route('/manageVehicles')
def MVehicles():
    admin_username = session.get('admin_username')
    return render_template('admin/manageVehicles.html', admin_username=admin_username)


if __name__ == '__main__':
    app.run(debug=True)

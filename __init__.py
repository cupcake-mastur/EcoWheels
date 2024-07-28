import html
import logging
import re
import stripe
import hashlib
import hmac
import os
import model
import random
import string
import secrets
import time

from flask import Flask, render_template, request, session, redirect, url_for, flash, current_app, jsonify, make_response, request, g
from flask_wtf import CSRFProtect
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from Forms import CreateUserForm, UpdateProfileForm, LoginForm, OTPForm, RequestPasswordResetForm, ResetPasswordForm, AdminLoginForm, CreateVehicleForm
from stack import *
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv, find_dotenv
from datetime import datetime, timedelta, timezone
from functools import wraps
from itsdangerous import URLSafeTimedSerializer
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exists, func
from werkzeug.utils import secure_filename
from PIL import Image
from model import *
from flask_wtf.csrf import generate_csrf, CSRFError
from werkzeug.exceptions import BadRequest
# ------------ For backup excel files -------------- #
from flask import send_file, jsonify
import pandas as pd
from io import BytesIO
import os
import openpyxl
from openpyxl import Workbook
from openpyxl.utils.dataframe import dataframe_to_rows
from openpyxl.drawing.image import Image as XLImage
from openpyxl.styles import PatternFill
# ------------------------------------------------- #

load_dotenv(find_dotenv())
db = SQLAlchemy()

app = Flask(__name__)

logging.basicConfig(filename='app.log', level=logging.INFO,
                    format=f'%(asctime)s %(levelname)s: %(message)s')

app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB limit

app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
s = URLSafeTimedSerializer(os.environ.get("SECRET_KEY"))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URI")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session timeout after 30 minutes

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
csrf = CSRFProtect(app)                                          # REMOVE IF NEEDED
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

with app.app_context():
    db.init_app(app)
    db.create_all()  # Create sql tables

#the stripe key for payment (SORRY ILL HIDE DIS LTR ON)
stripe.api_key = os.getenv('STRIPE_SECRET_KEY', 'sk_test_51Pe8BfFIE5otqt7EOKvQqa9Q21pxw6sOSStBTVsAqYPW89hggCJQjVoQd71erh65UnljQgmMPJDs0MnkkqsZ3E8C00WpoPI9Xz')

# Retrieve the latest 10 payment intents
payment_intents = stripe.PaymentIntent.list(limit=10)

for intent in payment_intents.data:
    print(f"Payment Intent ID: {intent.id}, Amount: {intent.amount}, Status: {intent.status}")


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_email' not in session:
            return redirect(url_for('login'))  # Redirect to login if user is not authenticated
        return f(*args, **kwargs)
    return decorated_function


def get_remote_address(request):
    return request.remote_addr

@limiter.request_filter
def exempt_routes():
    exempt_endpoints = ['createVehicle', 'system_createVehicle', 'MCustomers', 'system_MCustomers', 'MVehicles', 'system_MVehicles', 'system_logs', 'manageFeedback', 'system_manageFeedback'
                        'sub_dashboard', 'sub_MCustomers', 'sub_MVehicles', 'sub_manageFeedback']
    return request.endpoint in exempt_endpoints


@app.errorhandler(429)
def ratelimit_error(e):
    app.logger.warning(
        f"Rate limit exceeded for IP {get_remote_address(request)}. "
    )
    return render_template("customer/rate_limit_exceeded.html"), 429


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template('error_msg.html', reason=e.description), 400


@app.route('/')
def home():
    return render_template("homepage/homepage.html")


@app.route('/product_page')
def product_page():
    all_result = [
        # Example product data (seller, product)
        ('Seller1', {'get_product_id': lambda: 'prod_1', 'get_product_name': lambda: 'Product 1', 'get_product_price': lambda: 15.00, 'get_image': lambda: 'product1.jpg'}),
        ('Seller2', {'get_product_id': lambda: 'prod_2', 'get_product_name': lambda: 'Product 2', 'get_product_price': lambda: 5.00, 'get_image': lambda: 'product2.jpg'}),
        ('Seller3', {'get_product_id': lambda: 'prod_3', 'get_product_name': lambda: 'Product 3', 'get_product_price': lambda: 8.00, 'get_image': lambda: 'product3.jpg'}),
        ('Seller4', {'get_product_id': lambda: 'prod_4', 'get_product_name': lambda: 'Product 4', 'get_product_price': lambda: 2.00, 'get_image': lambda: 'product4.jpg'}),
    ]
    return render_template('customer/test_product_page(exists till terron creates one hehe).html', all_result=all_result)


@app.route('/models')
def models():
    vehicles = db.session.query(Vehicle).all()

    return render_template("homepage/models.html" , vehicles=vehicles)


@app.route('/Feedback', methods=['GET', 'POST'])
#@login_required                   #REMOVE COMMENT FOR USER LOG IN TO WORK, FOR TESTING CAN JUST LEAVE THE COMMENT
def feedback():
    if request.method == 'POST':
        email = request.form['email']
        message = request.form['feedback']
        email = request.form.get('email', 'default@example.com')

        # Handle the feedback (e.g., save to database)

        flash('Thank you for your feedback!', 'success')
        return redirect(url_for('thankyou'))

    # Pass the current user's username to the template
    #username = current_user.username
    return render_template('homepage/Feedback.html')


def admin_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_log_in'))  # Redirect to admin login if not logged in
        return f(*args, **kwargs)
    return decorated_function


@app.route('/manageFeedback')
@admin_login_required
def manageFeedback():
    admin_username = session.get('admin_username')

    # Query the Feedback table to get all feedback entries
    feedback_entries = Feedback.query.all()

    # Render the template with the feedback entries
    return render_template('admin/manageFeedback.html', admin_username=admin_username,
                           feedback_entries=feedback_entries)

@app.route('/thankyou')
def thankyou():
    return render_template("homepage/thankyou.html")


def track_user_visits(stack, url):
    stack.push(url)
    print(f"Visited: {url}")
    print(f"Current Stack: {stack._theItems}")


def get_last_visited_url(stack):
    if not stack.isEmpty():
        return stack.peek()
    else:
        return None


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
            special_chars = "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?"

            if any(char in special_chars for char in full_name) or any(char in special_chars for char in username):
                error = "Special characters are not allowed in the full name or username."
            elif not any(char in special_chars for char in password):
                error = "Password must contain at least one special character."    

        if error is None:
            hashed_password = generate_password_hash(password)
            new_user = User(full_name=full_name, username=username, email=email, phone_number=phone_number,
                            password_hash=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            password_history = PasswordHistory(user_id=new_user.id, password_hash=hashed_password, changed_at=datetime.now(timezone.utc))
            db.session.add(password_history)
            db.session.commit()
            app.logger.info(f"User {email} added to database.")
            return redirect(url_for('login'))
    return render_template("customer/sign_up.html", form=create_user_form, error=error)


def generate_otp(length=6):
    otp = ''.join(random.choices(string.digits, k=length))
    session['otp_generation_time'] = datetime.now(timezone.utc).timestamp()
    return otp


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    print(session)
    if session.get('user_logged_in'):
        return render_template('customer/error_msg_already_logged_in.html')

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
    msg.body = f'Your OTP code is: {otp}\n\nPlease note that this code will expire in 1 minute.'
    mail.send(msg)


@app.route('/request_new_otp', methods=['POST'])
def request_new_otp():
    user_email = session.get('user_email')
    session.pop('otp', None)
    new_otp = generate_otp()
    session['otp'] = new_otp
    send_otp_email(user_email, new_otp)
    app.logger.info(f"New OTP sent to {user_email}")

    return redirect(url_for('verify_otp'))


def hide_email(email):
    parts = email.split('@')
    return parts[0][:2] + '****' + parts[0][-2:] + '@' + parts[1]


app.jinja_env.filters['hide_email'] = hide_email


def hide_credit_card(card_number):
    # Assuming card_number is a string
    visible_digits = 4
    hidden_digits = len(card_number) - visible_digits
    return '****' * (hidden_digits // 4) + card_number[-visible_digits:]


app.jinja_env.filters['hide_credit_card'] = hide_credit_card


@app.route('/verify_otp', methods=['GET', 'POST'])
@login_required
def verify_otp():
    error = None
    user_email = session.get('user_email')
    otp_form = OTPForm(request.form)

    if not user_email:
        return redirect(url_for('login'))

    user = db.session.query(User).filter_by(email=user_email).first()
    if not user:
        return redirect(url_for('login'))

    if request.method == 'POST' and otp_form.validate():
        entered_otp_digits = [
            otp_form.otp1.data,
            otp_form.otp2.data,
            otp_form.otp3.data,
            otp_form.otp4.data,
            otp_form.otp5.data,
            otp_form.otp6.data
        ]
        entered_otp = ''.join(entered_otp_digits)
        print(entered_otp)
        otp = session.get('otp')
        otp_generation_time = session.get('otp_generation_time')
        current_time = datetime.now(timezone.utc).timestamp()

        if otp_generation_time and (current_time - otp_generation_time) <= 60:
            if entered_otp == otp:
                # Clear OTP from session
                session.pop('otp', None)
                session.pop('otp_generation_time', None)

                session['user'] = user_email  # Set user in session
                session['expiry_time'] = (datetime.now(timezone.utc) + app.config['PERMANENT_SESSION_LIFETIME']).timestamp()
                session['user_logged_in'] = True
                session.permanent = True

                app.logger.info(f"User {user_email} logged in successfully.")
                return redirect(url_for('home'))
            else:
                error = "Invalid OTP. Please try again."
                app.logger.warning(f"Invalid OTP attempt for {user_email}")
        else:
            error = "Invalid OTP. Please try again."
            app.logger.warning(f"Expired OTP attempt for {user_email}")

    return render_template('customer/verify_otp.html', form=otp_form, error=error, user_email=user_email)


@app.route('/profile', methods=['GET'])
@login_required
def profile():
    user_email = session.get('user_email')

    user = db.session.query(User).filter_by(email=user_email).first()

    if not user_email or not user:
        return redirect(url_for('login'))

    return render_template('customer/profile_page.html', user=user)


@app.route('/request_password_reset', methods=['GET', 'POST'])
def request_password_reset():
    error = None
    request_password_reset_form = RequestPasswordResetForm(request.form)
    if request.method == 'POST':
        email = request.form.get('email')
        user = db.session.query(User).filter_by(email=email).first()
        if user:
            token = s.dumps(email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)
            send_password_reset_email(email, reset_url)
            error = "A password reset link has been sent to your email."
            app.logger.info(f"Reset Link has been sent to {email} successfully.")
        else:
            error = "Email address not found"
    
    return render_template('customer/request_password_reset.html', form=request_password_reset_form, error=error)


def send_password_reset_email(email, reset_url):
    msg = Message('Password Reset Request', recipients=[email])
    msg.html = f'''
    <p>Click the link below to reset your password:</p>
    <p><a href="{reset_url}">Reset Password</a></p>
    <p>If you did not request this, please contact us at +6562911189.</p>
    '''
    mail.send(msg)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    error = None
    reset_password_form = ResetPasswordForm(request.form)
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        error = "The password reset link is invalid or has expired"
        app.logger.warning(f"Reset Link for {email} is invalid.")
        return redirect(url_for('request_password_reset'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            error = "Passwords do not match"
            return redirect(url_for('reset_password', token=token))

        user = db.session.query(User).filter_by(email=email).first()
        if user:
            user.password_hash = generate_password_hash(new_password)
            new_password_history = PasswordHistory(user_id=user.id, password_hash=user.password_hash)
            db.session.add(new_password_history)
            db.session.commit()
            return render_template('customer/password_reset_success.html')
        else:
            error = "An error occurred. Please try again."
            return redirect(url_for('request_password_reset'))

    return render_template('customer/reset_password.html', form=reset_password_form, token=token, error=error)


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    error = None
    user_email = session.get('user_email')
    user = db.session.query(User).filter_by(email=user_email).first()

    if not user:
        return redirect(url_for('login'))

    edit_profile_form = UpdateProfileForm(request.form, obj=user)

    if request.method == 'POST' and edit_profile_form.validate():
        form_type = request.form.get('form_type')
        print(f"Form Type Received: {form_type}")

        if form_type == 'general':
            full_name = edit_profile_form.full_name.data
            username = edit_profile_form.username.data
            email = edit_profile_form.email.data
            phone_number = edit_profile_form.phone_number.data
            current_password = edit_profile_form.current_password.data
            new_password = edit_profile_form.new_password.data
            confirm_new_password = edit_profile_form.confirm_new_password.data

            # Validate current password if provided
            if current_password and not check_password_hash(user.password_hash, current_password):
                error = 'Current password is incorrect.'
            elif new_password and new_password != confirm_new_password:
                error = 'New passwords do not match.'
            elif len(str(phone_number)) != 8:
                error = "Phone number must be 8 digits."
            else:
                special_chars = "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?"
                if any(char in special_chars for char in full_name) or any(char in special_chars for char in username):
                    error = "Special characters are not allowed in the full name or username."
                elif new_password and not any(char in special_chars for char in new_password):
                    error = "Password must contain at least one special character."    

                # Check last 3 passwords
                if not error:
                    recent_passwords = (db.session.query(PasswordHistory).filter_by(user_id=user.id).
                                        order_by(PasswordHistory.changed_at.desc()).limit(3).all())
                    for past_password in recent_passwords:
                        if check_password_hash(past_password.password_hash, new_password):
                            error = 'New password cannot be the same as any of the last 3 passwords.'
                            break

                if not error:
                    user.full_name = full_name
                    user.username = username
                    user.email = email
                    user.phone_number = phone_number

                    # Update password if new password is provided and matches confirmation
                    if new_password:
                        user.password_hash = generate_password_hash(new_password)
                        new_password_history = PasswordHistory(user_id=user.id, password_hash=user.password_hash)
                        db.session.add(new_password_history)

                        # Keep only the last 3 password hashes
                        # Most recent password changes are listed first (because of the desc)
                        all_passwords = (db.session.query(PasswordHistory).filter_by(user_id=user.id).
                                         order_by(PasswordHistory.changed_at.desc()).all())
                        if len(all_passwords) > 3:
                            for old_password in all_passwords[3:]:
                                db.session.delete(old_password)

        elif form_type == 'payment':
            card_name = edit_profile_form.card_name.data
            card_number = edit_profile_form.card_number.data
            exp_month = edit_profile_form.exp_month.data
            exp_year = edit_profile_form.exp_year.data
            cvv = edit_profile_form.cvv.data
            #Add validation
            user.card_name = card_name
            user.card_number = card_number
            user.exp_month = exp_month
            user.exp_year = exp_year
            user.cvv = cvv

        if error:
            return render_template('customer/edit_profile.html', user=user, form=edit_profile_form, error=error)

        db.session.commit()
        error = 'Profile updated successfully.'

    return render_template('customer/edit_profile.html', user=user, form=edit_profile_form, error=error)


@app.route('/user/logout')
def logout():
    if 'user_email' in session:
        user_email = session.pop('user_email', None)
        app.logger.info(f"User {user_email} logged out successfully.")
        session.clear()
        session.modified = True
        print(session)
        return render_template('customer/logout_message.html')
    else:
        return render_template('customer/error_msg_not_logged_in.html')


@app.before_request
def before_request():
    if 'user_email' in session:
        current_time = datetime.now(timezone.utc).timestamp()
        if 'expiry_time' in session and current_time > session['expiry_time']:
            session.clear()
            session.modified = True
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify(expired=True), 401  # Return JSON for the AJAX request

        if request.headers.get('X-Check-Session') != 'True':
            session['expiry_time'] = (datetime.now(timezone.utc) + app.config['PERMANENT_SESSION_LIFETIME']).timestamp()
            session.modified = True

@app.route('/cart')
def cart_page():
    return render_template('customer/shopping_cart.html')

@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    try:
        data = request.get_json()
        line_items = [{
            'price_data': {
                'currency': 'usd',
                'product_data': {
                    'name': item['name'],
                },
                'unit_amount': int(item['price'] * 100),  # Stripe expects the amount in cents
            },
            'quantity': 1,
        } for item in data]

        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=line_items,
            mode='payment',
            success_url='http://127.0.0.1:5000/payment_success',  # Update with your success URL
            cancel_url='http://yourdomain.com/cancel',  # Update with your cancel URL
        )

        return jsonify({'url': session.url})
    except Exception as e:
        return jsonify(error=str(e)), 403

@app.route('/payment_success')
def success_page():
    return render_template('customer/payment_success.html')

@app.route('/cancel')
def cancel_page():
    return "Payment Cancelled"
# @app.route('/payment')
# def payment():
#     return render_template("customer/payment.html")


# @app.route('/confirmation')
# def confirmation():
#     # Render a simple confirmation page
#     return "Thank you for your order!"


# NEED TO METHOD = 'POST' THESE ADMIN PAGES
admin_list = ['LiamThompson@ecowheels.com', 'OliviaBrown@ecowheels.com', 'testuser@ecowheels.com']
system_admin_list = ['SophiaMartinez@ecowheels.com', 'JamesCarter@ecowheels.com', 'testusersa@ecowheels.com']
SGT = pytz.timezone('Asia/Singapore')
vehicle_backup_time = []
customer_backup_time = []
logs_backup_time = []


# Log event function
def log_event(event_type, event_result):
    log = Log(event_type=event_type, event_result=event_result)
    db.session.add(log)
    db.session.commit()


def role_required(*roles):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'admin_logged_in' not in session:
                return redirect(url_for('admin_log_in'))

            if session.get('admin_role') not in roles:
                return redirect(url_for('ErrorPage'))

            return f(*args, **kwargs)

        return decorated_function

    return wrapper


def admin_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_log_in'))  # Redirect to admin login if not logged in
        return f(*args, **kwargs)

    return decorated_function


@app.route('/admin_log_in', methods=['GET', 'POST'])
def admin_log_in():
    form = AdminLoginForm()
    error_message = None
    if form.validate_on_submit():
        username = html.escape(form.username.data)
        password = html.escape(form.password.data)

        if not username.endswith('@ecowheels.com'):
            error_message = "Incorrect Username or Password"
            return render_template('admin/admin_log_in.html', form=form, error_message=error_message)

        admin = db.session.query(Admin).filter(func.binary(Admin.username) == username).first()

        if admin:
            if admin.is_suspended:
                error_message = "Your account is suspended due to too many failed login attempts."
                return render_template('admin/admin_log_in.html', form=form, error_message=error_message)

            if admin.check_password(password):
                admin.login_attempts = 0
                db.session.commit()

                session['admin_username'] = username
                session['admin_logged_in'] = True

                if username not in admin_list and username not in system_admin_list:
                    session['admin_role'] = 'junior'
                    log_event('Login', f'Successful login for junior admin {username}.')
                    return redirect(url_for('sub_dashboard'))

                elif username in admin_list:
                    session['admin_role'] = 'general'
                    log_event('Login', f'Successful login for admin {username}.')
                    return redirect(url_for('dashboard'))

                elif username in system_admin_list:
                    session['admin_role'] = 'system'
                    log_event('Login', f'Successful login for system admin {username}.')
                    return redirect(url_for('system_dashboard'))
            else:
                admin.login_attempts += 1
                log_event('Login', f'Failed login attempt for admin {username}. Attempt {admin.login_attempts}')

                if admin.login_attempts >= 3:
                    admin.is_suspended = True
                    log_event('Login',
                              f'Account for admin {username} is suspended due to too many failed login attempts.')

                db.session.commit()
                error_message = "Incorrect Username or Password"
        else:
            error_message = "Incorrect Username or Password"
            log_event('Login', f'Failed login attempt for non-existent admin {username}.')

    return render_template('admin/admin_log_in.html', form=form, error_message=error_message)


def is_valid_input(input_str):
    """
    Check if the input string contains only allowed characters.
    """
    # Define a regular expression to match allowed characters
    allowed_chars_pattern = re.compile(r'^[\w.@+-]+$')
    return bool(allowed_chars_pattern.match(input_str))


def save_image_file(form_file):
    if not form_file or not form_file.filename:
        raise BadRequest("No file provided or invalid file.")

    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_file.filename)
    picture_fn = random_hex + f_ext.lower()  # Ensure lowercase extension
    picture_path = os.path.join(current_app.root_path, 'static/vehicle_images', picture_fn)

    # Check if the provided file is a directory before saving
    if hasattr(form_file, 'read'):
        form_file.seek(0)
        form_file.save(picture_path)
    else:
        raise BadRequest("Uploaded data is not a valid file.")

    # Check if the saved file is actually a file
    if os.path.isdir(picture_path):
        os.remove(picture_path)
        raise BadRequest("Uploaded data is a directory, not a file.")

    try:
        Image.open(picture_path).verify()
    except Exception:
        os.remove(picture_path)  # Remove the file if verification fails
        raise ValueError("Invalid image file.")

    return picture_fn


@app.route('/createVehicle', methods=['GET', 'POST'])
@role_required('general')
@admin_login_required
def createVehicle():
    create_vehicle_form = CreateVehicleForm()
    if request.method == 'POST' and create_vehicle_form.validate_on_submit():
        brand = create_vehicle_form.brand.data
        model = create_vehicle_form.model.data
        price = create_vehicle_form.price.data
        description = create_vehicle_form.description.data

        if create_vehicle_form.file.data:
            try:
                file = save_image_file(create_vehicle_form.file.data)
            except (BadRequest, ValueError) as e:
                return redirect(url_for('ErrorPage'))
        else:
            file = None

        try:
            new_vehicle = Vehicle(brand=brand, model=model, selling_price=price, image=file, description=description)
            db.session.add(new_vehicle)
            db.session.commit()
            log_event('Create Vehicle', f'New vehicle created: {brand} {model} by {session["admin_username"]}.')
            return redirect(url_for('MVehicles'))
        except Exception:
            db.session.rollback()

    return render_template('admin/createVehicleForm.html', form=create_vehicle_form)


@app.route('/system_createVehicle', methods=['GET', 'POST'])
@role_required('system')
@admin_login_required
def system_createVehicle():
    create_vehicle_form = CreateVehicleForm()
    if request.method == 'POST' and create_vehicle_form.validate_on_submit():
        brand = create_vehicle_form.brand.data
        model = create_vehicle_form.model.data
        price = create_vehicle_form.price.data
        description = create_vehicle_form.description.data

        if create_vehicle_form.file.data:
            try:
                file = save_image_file(create_vehicle_form.file.data)
            except (BadRequest, ValueError) as e:
                return redirect(url_for('ErrorPage'))
        else:
            file = None

        try:
            new_vehicle = Vehicle(brand=brand, model=model, selling_price=price, image=file, description=description)
            db.session.add(new_vehicle)
            db.session.commit()
            log_event('Create Vehicle', f'New vehicle created: {brand} {model} by {session["admin_username"]}.')
            return redirect(url_for('system_MVehicles'))
        except Exception:
            db.session.rollback()

    return render_template('admin/system_admin/system_createVehicleForm.html', form=create_vehicle_form)


@app.route('/ErrorPage')
def ErrorPage():
    referrer = request.referrer or url_for('home')  # Default to 'home' if no referrer
    return render_template('admin/ErrorPage.html', referrer=referrer)


@app.route('/dashboard', methods=['GET', 'POST'])
@admin_login_required
@role_required('general')
def dashboard():
    admin_username = session.get('admin_username')
    num_customers = db.session.query(User).count()
    num_vehicles = db.session.query(Vehicle).count()
    num_admins = db.session.query(Admin).count()
    return render_template('admin/dashboard.html', admin_username=admin_username,
                           num_customers=num_customers, num_vehicles=num_vehicles, num_admins=num_admins)


@app.route('/system_admin_dashboard', methods=['GET', 'POST'])
@admin_login_required
@role_required('system')
def system_dashboard():
    admin_username = session.get('admin_username')
    num_customers = db.session.query(User).count()
    num_vehicles = db.session.query(Vehicle).count()
    num_admins = db.session.query(Admin).count()
    return render_template('admin/system_admin/system_dashboard.html', admin_username=admin_username,
                           num_customers=num_customers, num_vehicles=num_vehicles, num_admins=num_admins)


@app.route('/sub_dashboard', methods=['GET', 'POST'])
@admin_login_required
@role_required('junior')
def sub_dashboard():
    admin_username = session.get('admin_username')
    num_customers = db.session.query(User).count()
    num_vehicles = db.session.query(Vehicle).count()
    num_admins = db.session.query(Admin).count()
    return render_template('admin/junior_admin/sub_dashboard.html', admin_username=admin_username,
                           num_customers=num_customers, num_vehicles=num_vehicles, num_admins=num_admins)


@app.route('/manageCustomers', methods=['GET', 'POST'])
@admin_login_required
@role_required('general')
def MCustomers():
    admin_username = session.get('admin_username')
    csrf_token = generate_csrf()  # Generate CSRF token
    query = db.session.query(User)
    errors = {}

    if request.method == 'POST':
        full_name_filter = request.form.get('full_name_filter')
        username_filter = request.form.get('username_filter')
        email_filter = request.form.get('email_filter')
        phone_number_filter = request.form.get('phone_number_filter')

        if full_name_filter and is_valid_input(full_name_filter):
            query = query.filter(User.full_name.ilike(f"%{full_name_filter}%"))
        elif full_name_filter:
            errors['full_name_filter'] = 'Invalid input for full name filter'

        if username_filter and is_valid_input(username_filter):
            query = query.filter(User.username.ilike(f"%{username_filter}%"))
        elif username_filter:
            errors['username_filter'] = 'Invalid input for username filter'

        if email_filter and is_valid_input(email_filter):
            query = query.filter(User.email.ilike(f"%{email_filter}%"))
        elif email_filter:
            errors['email_filter'] = 'Invalid input for email filter'

        if phone_number_filter and is_valid_input(phone_number_filter):
            query = query.filter(User.phone_number.ilike(f"%{phone_number_filter}%"))
        elif phone_number_filter:
            errors['phone_number_filter'] = 'Invalid input for phone number filter'

    customers = query.all()

    return render_template('admin/manageCustomers.html', admin_username=admin_username, customers=customers,
                           csrf_token=csrf_token, errors=errors)


@app.route('/system_manageCustomers', methods=['GET', 'POST'])
@admin_login_required
@role_required('system')
def system_MCustomers():
    admin_username = session.get('admin_username')
    csrf_token = generate_csrf()  # Generate CSRF token
    query = db.session.query(User)
    errors = {}
    if request.method == 'POST':
        full_name_filter = request.form.get('full_name_filter')
        username_filter = request.form.get('username_filter')
        email_filter = request.form.get('email_filter')
        phone_number_filter = request.form.get('phone_number_filter')

        if full_name_filter and is_valid_input(full_name_filter):
            query = query.filter(User.full_name.ilike(f"%{full_name_filter}%"))
        elif full_name_filter:
            errors['full_name_filter'] = 'Invalid input for full name filter'

        if username_filter and is_valid_input(username_filter):
            query = query.filter(User.username.ilike(f"%{username_filter}%"))
        elif username_filter:
            errors['username_filter'] = 'Invalid input for username filter'

        if email_filter and is_valid_input(email_filter):
            query = query.filter(User.email.ilike(f"%{email_filter}%"))
        elif email_filter:
            errors['email_filter'] = 'Invalid input for email filter'

        if phone_number_filter and is_valid_input(phone_number_filter):
            query = query.filter(User.phone_number.ilike(f"%{phone_number_filter}%"))
        elif phone_number_filter:
            errors['phone_number_filter'] = 'Invalid input for phone number filter'

    customers = query.all()

    return render_template('admin/system_admin/system_manageCustomers.html', admin_username=admin_username,
                           customers=customers, csrf_token=csrf_token, errors=errors,
                           customer_backup_time=customer_backup_time)


@app.route('/sub_manageCustomers', methods=['GET', 'POST'])
@admin_login_required
@role_required('junior')
def sub_MCustomers():
    admin_username = session.get('admin_username')
    csrf_token = generate_csrf()  # Generate CSRF token
    errors = {}

    query = db.session.query(User)
    if request.method == 'POST':
        full_name_filter = request.form.get('full_name_filter')
        username_filter = request.form.get('username_filter')
        email_filter = request.form.get('email_filter')
        phone_number_filter = request.form.get('phone_number_filter')

        if full_name_filter and is_valid_input(full_name_filter):
            query = query.filter(User.full_name.ilike(f"%{full_name_filter}%"))
        elif full_name_filter:
            errors['full_name_filter'] = 'Invalid input for full name filter'

        if username_filter and is_valid_input(username_filter):
            query = query.filter(User.username.ilike(f"%{username_filter}%"))
        elif username_filter:
            errors['username_filter'] = 'Invalid input for username filter'

        if email_filter and is_valid_input(email_filter):
            query = query.filter(User.email.ilike(f"%{email_filter}%"))
        elif email_filter:
            errors['email_filter'] = 'Invalid input for email filter'

        if phone_number_filter and is_valid_input(phone_number_filter):
            query = query.filter(User.phone_number.ilike(f"%{phone_number_filter}%"))
        elif phone_number_filter:
            errors['phone_number_filter'] = 'Invalid input for phone number filter'

    customers = query.all()

    return render_template('admin/junior_admin/sub_manageCustomers.html', admin_username=admin_username,
                           customers=customers
                           , csrf_token=csrf_token, errors=errors)


@app.route('/manageVehicles', methods=['GET', 'POST'])
@admin_login_required
@role_required('general')
def MVehicles():
    admin_username = session.get('admin_username')
    csrf_token = generate_csrf()  # Generate CSRF token
    vehicles = db.session.query(Vehicle).all()
    errors = {}

    if request.method == 'POST':
        brand_filter = request.form.get('brand_filter')
        model_filter = request.form.get('model_filter')
        min_price_filter = request.form.get('min_price_filter')
        max_price_filter = request.form.get('max_price_filter')

        query = db.session.query(Vehicle)
        if brand_filter and is_valid_input(brand_filter):
            query = query.filter(Vehicle.brand.ilike(f"%{brand_filter}%"))
        elif brand_filter:
            errors['brand_filter'] = 'Invalid input for brand filter'

        if model_filter and is_valid_input(model_filter):
            query = query.filter(Vehicle.model.ilike(f"%{model_filter}%"))
        elif model_filter:
            errors['model_filter'] = 'Invalid input for model filter'

        if min_price_filter and is_valid_input(min_price_filter):
            query = query.filter(Vehicle.selling_price >= float(min_price_filter))
        elif min_price_filter:
            errors['min_price_filter'] = 'Invalid input for minimum price filter'

        if max_price_filter and is_valid_input(max_price_filter):
            query = query.filter(Vehicle.selling_price <= float(max_price_filter))
        elif max_price_filter:
            errors['max_price_filter'] = 'Invalid input for maximum price filter'

        vehicles = query.all()

    return render_template('admin/manageVehicles.html', admin_username=admin_username, vehicles=vehicles,
                           csrf_token=csrf_token, errors=errors)


@app.route('/system_manageVehicles', methods=['GET', 'POST'])
@admin_login_required
@role_required('system')
def system_MVehicles():
    admin_username = session.get('admin_username')
    csrf_token = generate_csrf()  # Generate CSRF token
    vehicles = db.session.query(Vehicle).all()
    errors = {}

    if request.method == 'POST':
        brand_filter = request.form.get('brand_filter')
        model_filter = request.form.get('model_filter')
        min_price_filter = request.form.get('min_price_filter')
        max_price_filter = request.form.get('max_price_filter')

        query = db.session.query(Vehicle)
        if brand_filter and is_valid_input(brand_filter):
            query = query.filter(Vehicle.brand.ilike(f"%{brand_filter}%"))
        elif brand_filter:
            errors['brand_filter'] = 'Invalid input for brand filter'

        if model_filter and is_valid_input(model_filter):
            query = query.filter(Vehicle.model.ilike(f"%{model_filter}%"))
        elif model_filter:
            errors['model_filter'] = 'Invalid input for model filter'

        if min_price_filter and is_valid_input(min_price_filter):
            query = query.filter(Vehicle.selling_price >= float(min_price_filter))
        elif min_price_filter:
            errors['min_price_filter'] = 'Invalid input for minimum price filter'

        if max_price_filter and is_valid_input(max_price_filter):
            query = query.filter(Vehicle.selling_price <= float(max_price_filter))
        elif max_price_filter:
            errors['max_price_filter'] = 'Invalid input for maximum price filter'

        vehicles = query.all()

    return render_template('admin/system_admin/system_manageVehicles.html', admin_username=admin_username,
                           vehicles=vehicles, csrf_token=csrf_token, errors=errors,
                           vehicle_backup_time=vehicle_backup_time)


@app.route('/sub_manageVehicles', methods=['GET', 'POST'])
@admin_login_required
@role_required('junior')
def sub_MVehicles():
    admin_username = session.get('admin_username')
    csrf_token = generate_csrf()  # Generate CSRF token
    vehicles = db.session.query(Vehicle).all()
    errors = {}

    if request.method == 'POST':
        brand_filter = request.form.get('brand_filter')
        model_filter = request.form.get('model_filter')
        min_price_filter = request.form.get('min_price_filter')
        max_price_filter = request.form.get('max_price_filter')

        query = db.session.query(Vehicle)
        if brand_filter and is_valid_input(brand_filter):
            query = query.filter(Vehicle.brand.ilike(f"%{brand_filter}%"))
        elif brand_filter:
            errors['brand_filter'] = 'Invalid input for brand filter'

        if model_filter and is_valid_input(model_filter):
            query = query.filter(Vehicle.model.ilike(f"%{model_filter}%"))
        elif model_filter:
            errors['model_filter'] = 'Invalid input for model filter'

        if min_price_filter and is_valid_input(min_price_filter):
            query = query.filter(Vehicle.selling_price >= float(min_price_filter))
        elif min_price_filter:
            errors['min_price_filter'] = 'Invalid input for minimum price filter'

        if max_price_filter and is_valid_input(max_price_filter):
            query = query.filter(Vehicle.selling_price <= float(max_price_filter))
        elif max_price_filter:
            errors['max_price_filter'] = 'Invalid input for maximum price filter'

        vehicles = query.all()

    return render_template('admin/junior_admin/sub_manageVehicles.html', admin_username=admin_username,
                           vehicles=vehicles,
                           csrf_token=csrf_token, errors=errors)


@app.route('/delete_vehicle/<int:id>', methods=['POST'])
@admin_login_required
def delete_vehicle(id):
    vehicle = db.session.query(Vehicle).get(id)
    if vehicle:
        db.session.delete(vehicle)
        db.session.commit()
        log_event('Delete Vehicle', f'Vehicle deleted: {vehicle.brand} {vehicle.model} by {session["admin_username"]}.')
    if session['admin_role'] == 'system':
        return redirect(url_for('system_MVehicles'))
    elif session['admin_role'] == 'general':
        return redirect(url_for('MVehicles'))
    else:
        return redirect(url_for('ErrorPage'))


@app.route('/logs', methods=['GET', 'POST'])
@admin_login_required
@role_required('system')
def system_logs():
    admin_username = session.get('admin_username')
    csrf_token = generate_csrf()  # Generate CSRF token
    errors = {}
    if request.method == 'POST':
        event_type = request.form.get('event_type')
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')
        keyword = request.form.get('keyword')

        query = db.session.query(Log)

        if event_type and is_valid_input(event_type):
            query = query.filter(Log.event_type == event_type)

        if start_date:
            start_datetime = datetime.strptime(start_date, '%Y-%m-%dT%H:%M')
            query = query.filter(Log.event_time >= start_datetime)

        if end_date:
            end_datetime = datetime.strptime(end_date, '%Y-%m-%dT%H:%M')
            query = query.filter(Log.event_time <= end_datetime)

        if keyword and is_valid_input(keyword):
            query = query.filter(Log.event_result.ilike(f'%{keyword}%'))
        elif keyword:
            errors['keyword'] = 'Invalid input for keyword'

        logs = query.all()
    else:
        logs = db.session.query(Log).all()

    return render_template('admin/system_admin/logs.html', admin_username=admin_username, logs=logs
                           , csrf_token=csrf_token, errors=errors, logs_backup_time=logs_backup_time)


@app.route('/system_manageFeedback')
@admin_login_required
@role_required('system')
def system_manageFeedback():
    admin_username = session.get('admin_username')
    return render_template('admin/system_admin/system_manageFeedback.html', admin_username=admin_username)


@app.route('/sub_manageFeedback')
@admin_login_required
@role_required('junior')
def sub_manageFeedback():
    admin_username = session.get('admin_username')
    return render_template('admin/junior_admin/sub_manageFeedback.html', admin_username=admin_username)


@app.route('/system_manageAdmin', methods=['GET'])
@admin_login_required
@role_required('system')
def system_manageAdmin():
    admin_username = session.get('admin_username')
    csrf_token = generate_csrf()  # Generate CSRF token
    errors = {}
    if 'admin_logged_in' in session and session['admin_role'] == 'system':
        admins = db.session.query(Admin).all()
        suspended_admins = db.session.query(Admin).filter_by(is_suspended=True).all()
        return render_template('admin/system_admin/system_manageAdmins.html', suspended_admins=suspended_admins,
                               admin_username=admin_username, admins=admins, errors=errors, csrf_token=csrf_token)
    else:
        return redirect(url_for('admin_log_in'))


@app.route('/unsuspend_admin', methods=['POST'])
@admin_login_required
@role_required('system')
def unsuspend_admin(id):
    if 'admin_logged_in' in session and session['admin_role'] == 'system':
        username = request.form.get('username')
        password = request.form.get('password')

        admin = db.session.query(Admin).filter_by(username=username).first()
        system_admin = db.session.query(Admin).filter_by(username=session['admin_username']).first()

        if admin and system_admin and system_admin.check_password(password):
            admin.is_suspended = False
            admin.login_attempts = 0
            db.session.commit()
            log_event('Unsuspend',
                      f'Successful unsuspension of admin {username} by system admin {system_admin.username}.')
            flash(f'Admin {username} has been unsuspended.', 'success')
        else:
            log_event('Unsuspend',
                      f'Failed unsuspension attempt for admin {username} by system admin {system_admin.username} (incorrect password).')
            flash('Incorrect password. Unsuspension failed.', 'danger')


@app.route('/admin_logout')
def admin_logout():
    if 'admin_logged_in' in session:
        admin_username = session.get('admin_username')
        if session['admin_role'] == 'system':
            log_event('Logout', f'Successfully logged out system admin {admin_username}')
        elif session['admin_role'] == 'junior':
            log_event('Logout', f'Successfully logged out junior admin {admin_username}')
        else:
            log_event('Logout', f'Successfully logged out admin {admin_username}')
        session.clear()  # Clear all session data
        return redirect(url_for('admin_log_in'))
    else:
        return "Admin is not logged in."


@app.route('/backup_vehicles', methods=['GET'])
@admin_login_required
@role_required('system')
def backup_vehicles():
    vehicles = db.session.query(Vehicle).all()
    backup_time = datetime.now(SGT).strftime('%d-%m-%Y, %I:%M:%S %p')  # Use the new format
    vehicle_backup_time.append(backup_time)
    admin_username = session.get('admin_username')
    log_event('Backup', f'Backed up Vehicles database by {admin_username}')

    # Create a DataFrame
    vehicle_data = []
    for vehicle in vehicles:
        vehicle_data.append({
            'Vehicle ID': vehicle.idvehicles,
            'Brand': vehicle.brand,
            'Model': vehicle.model,
            'Selling Price': vehicle.selling_price,
            'Image': vehicle.image,
            'Description': vehicle.description
        })

    df = pd.DataFrame(vehicle_data)

    # Create an Excel workbook and sheet
    wb = Workbook()
    ws = wb.active
    ws.title = "Vehicles"

    # Write the DataFrame to the Excel sheet
    for r_idx, row in enumerate(dataframe_to_rows(df, index=False, header=True), start=1):
        for c_idx, value in enumerate(row, start=1):
            ws.cell(row=r_idx, column=c_idx, value=value)

    # Add images to the Excel sheet
    row_index = 2  # Start from the second row
    for vehicle in vehicles:
        if vehicle.image:
            img_path = os.path.join(app.static_folder, 'vehicle_images', vehicle.image)
            if os.path.exists(img_path):
                img = XLImage(img_path)
                img.height = 100  # Set image height
                img.width = 100  # Set image width
                ws.add_image(img, f'E{row_index}')  # Place the image in the correct cell
        row_index += 1  # Increment the row index

    output = BytesIO()
    wb.save(output)
    output.seek(0)

    # Send the file to the user
    return send_file(output, download_name='backupVehicle.xlsx', as_attachment=True)


@app.route('/backup_customers', methods=['GET'])
@admin_login_required
@role_required('system')
def backup_customers():
    # Query all customers from the database
    customers = db.session.query(User).all()
    backup_time = datetime.now(SGT).strftime('%d-%m-%Y, %I:%M:%S %p')  # Use the new format
    customer_backup_time.append(backup_time)
    admin_username = session.get('admin_username')
    log_event('Backup', f'Backed up Customers database by {admin_username}')

    # Create a DataFrame with relevant customer data
    customer_data = []
    for customer in customers:
        customer_data.append({
            'Customer ID': customer.id,
            'Full Name': customer.full_name,
            'Username': customer.username,
            'Email': customer.email,
            'Phone Number': customer.phone_number
        })

    df = pd.DataFrame(customer_data)

    # Create an Excel workbook and sheet
    wb = Workbook()
    ws = wb.active
    ws.title = "Customers"

    # Write the DataFrame to the Excel sheet
    for r_idx, row in enumerate(dataframe_to_rows(df, index=False, header=True), start=1):
        for c_idx, value in enumerate(row, start=1):
            ws.cell(row=r_idx, column=c_idx, value=value)

    # Save the Excel file to a BytesIO object
    output = BytesIO()
    wb.save(output)
    output.seek(0)

    # Send the file to the user
    return send_file(output, download_name='backupCustomers.xlsx', as_attachment=True)


@app.route('/backup_logs', methods=['GET'])
@admin_login_required
@role_required('system')
def backup_logs():
    logs = db.session.query(Log).all()
    backup_time = datetime.now(SGT).strftime('%d-%m-%Y, %I:%M:%S %p')  # Use the new format
    logs_backup_time.append(backup_time)
    admin_username = session.get('admin_username')
    log_event('Backup', f'Backed up Logs database by {admin_username}')

    # Create a DataFrame
    log_data = []
    for log in logs:
        log_data.append({
            'Log ID': log.id,
            'Event Type': log.event_type,
            'Event Time': log.event_time.strftime('%Y-%m-%d %H:%M:%S'),
            'Event Result': log.event_result
        })

    df = pd.DataFrame(log_data)

    # Create an Excel workbook and sheet
    wb = Workbook()
    ws = wb.active
    ws.title = "Logs"

    # Define color fills for different event types
    colors = {
        'Login': '7dde8b',  # Light green
        'Logout': '7dde8b',  # Light green
        'Create Vehicle': 'f5c842',  # Light orange
        'Delete Vehicle': 'faa441',  # Light orange
        'Backup': 'c2c2c2'  # Light gray
    }

    # Apply header styles
    header_fill = PatternFill(start_color='d9ead3', end_color='d9ead3', fill_type='solid')
    for c in range(1, len(df.columns) + 1):
        ws.cell(row=1, column=c).fill = header_fill

    # Write the DataFrame to the Excel sheet
    for r_idx, row in enumerate(dataframe_to_rows(df, index=False, header=True), start=1):
        for c_idx, value in enumerate(row, start=1):
            cell = ws.cell(row=r_idx, column=c_idx, value=value)

            # Apply color based on event type
            if r_idx > 1:  # Skip header row
                event_type = df.iloc[r_idx - 2]['Event Type']
                color = colors.get(event_type, 'ffffff')  # Default to white if no color found
                cell.fill = PatternFill(start_color=color, end_color=color, fill_type='solid')

    output = BytesIO()
    wb.save(output)
    output.seek(0)

    # Send the file to the user
    return send_file(output, download_name='backupLogs.xlsx', as_attachment=True)
  
if __name__ == '__main__':
    app.run(debug=True)

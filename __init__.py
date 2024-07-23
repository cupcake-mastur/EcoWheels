import html
import logging
import re
import stripe

from flask import Flask, render_template, request, session, redirect, url_for, flash, current_app, jsonify, make_response, request
from flask_mail import Mail, Message
from Forms import CreateUserForm, UpdateProfileForm, LoginForm, RequestPasswordResetForm, ResetPasswordForm, AdminLoginForm, CreateVehicleForm
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv, find_dotenv
from datetime import datetime, timedelta, timezone
from functools import wraps
from itsdangerous import URLSafeTimedSerializer
import hashlib
import hmac
import os
import model
import random
import string
import secrets
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exists, func
from werkzeug.utils import secure_filename
from PIL import Image
import stripe

from model import *

load_dotenv(find_dotenv())
db = SQLAlchemy()

app = Flask(__name__)

logging.basicConfig(filename='app.log', level=logging.DEBUG,
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

with app.app_context():
    db.init_app(app)
    db.create_all()  # Create sql tables

#the stripe key for payment (SORRY ILL HIDE DIS LTR ON)
stripe.api_key = os.getenv('STRIPE_SECRET_KEY', 'sk_test_51Pe8BfFIE5otqt7EOKvQqa9Q21pxw6sOSStBTVsAqYPW89hggCJQjVoQd71erh65UnljQgmMPJDs0MnkkqsZ3E8C00WpoPI9Xz')

# Retrieve the latest 10 payment intents
payment_intents = stripe.PaymentIntent.list(limit=10)

for intent in payment_intents.data:
    print(f"Payment Intent ID: {intent.id}, Amount: {intent.amount}, Status: {intent.status}")


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

@app.route('/Feedback')
def feedback():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']

        # Handle the feedback (e.g., save to database)

        flash('Thank you for your feedback!', 'success')
        return redirect(url_for('feedback'))

    # Pass the current user's username to the template
    #username = current_user.username
    return render_template('homepage/Feedback.html')



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


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_email' not in session:
            return redirect(url_for('login'))  # Redirect to login if user is not authenticated
        return f(*args, **kwargs)
    return decorated_function


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

    if not user_email:
        return redirect(url_for('login'))

    user = db.session.query(User).filter_by(email=user_email).first()
    if not user:
        return redirect(url_for('login'))

    if request.method == 'POST':
        entered_otp_digits = [request.form.get(f'otp{i}') for i in range(1, 7)]
        entered_otp = ''.join(entered_otp_digits)
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
                return redirect(user.last_visited_url)
            else:
                error = "Invalid OTP. Please try again."
                app.logger.warning(f"Invalid OTP attempt for {user_email}")
        else:
            error = "OTP has expired. Please request a new OTP."
            app.logger.warning(f"Expired OTP attempt for {user_email}")

    return render_template('customer/verify_otp.html', error=error, user_email=user_email)


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
            send_password_reset_email(email, reset_url)  # Implement this function
            error = "A password reset link has been sent to your email."
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
            error = "Your password has been reset"
            return redirect(url_for('login'))
        else:
            error = "An error occurred. Please try again"
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
            # Need to add validation
            user.card_name = edit_profile_form.card_name.data
            user.card_number = edit_profile_form.card_number.data
            user.exp_month = edit_profile_form.exp_month.data
            user.exp_year = edit_profile_form.exp_year.data
            user.cvv = edit_profile_form.cvv.data

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
        return redirect(url_for('home'))
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
# Log event function
def log_event(event_type, event_result):
    log = Log(event_type=event_type, event_result=event_result)
    db.session.add(log)
    db.session.commit()

@app.route('/admin_log_in', methods=['GET', 'POST'])
def admin_log_in():
    form = AdminLoginForm(request.form)
    error_message = None
    if form.validate_on_submit():
        username = html.escape(form.username.data)
        password = html.escape(form.password.data)

        if not form.username.validate(form) or not form.password.validate(form):
            return render_template('admin/admin_log_in.html', form=form)

        if not is_valid_input(username) or not is_valid_input(password):
            return render_template('admin/admin_log_in.html', form=form)

        admin = db.session.query(Admin).filter(func.binary(Admin.username) == username).first()

        if admin and admin.check_password(password):
            session['admin_username'] = username
            session['admin_logged_in'] = True
            log_event('Login', f'Successful login for username {username}.')
            return redirect(url_for('dashboard'))
        else:
            error_message = "Incorrect Username or Password"
            log_event('Login', f'Failed login attempt for username {username}.')

    return render_template('admin/admin_log_in.html', form=form, error_message=error_message)

def admin_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_log_in'))  # Redirect to admin login if not logged in
        return f(*args, **kwargs)
    return decorated_function

def is_valid_input(input_str):
    """
    Check if the input string contains only allowed characters.
    """
    # Define a regular expression to match allowed characters
    allowed_chars_pattern = re.compile(r'^[\w.@+-]+$')
    return bool(allowed_chars_pattern.match(input_str))



def save_image_file(form_file):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_file.filename)
    picture_fn = random_hex + f_ext.lower()  # Ensure lowercase extension
    picture_path = os.path.join(current_app.root_path, 'static/vehicle_images', picture_fn)

    # Save file securely
    form_file.save(picture_path)

    try:
        Image.open(picture_path).verify()
    except Exception as e:
        os.remove(picture_path)  # Remove the file if verification fails
        raise ValueError("Invalid image file.")

    return picture_fn


@app.route('/createVehicle', methods=['GET', 'POST'])
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
            except IsADirectoryError:
                return redirect(url_for('ErrorPage'))
            except ValueError:
                return redirect(url_for('ErrorPage'))
        else:
            file = None

        try:
            new_vehicle = Vehicle(brand=brand, model=model, selling_price=price, image=file, description=description)
            db.session.add(new_vehicle)
            db.session.commit()
            log_event('Create Vehicle', f'New vehicle created: {brand} {model} by {session["admin_username"]}.')
            return redirect(url_for('MVehicles'))
        except Exception as e:
            db.session.rollback()

    return render_template('admin/createVehicleForm.html', form=create_vehicle_form)

@app.route('/ErrorPage')
def ErrorPage():
    return render_template('admin/ErrorPage.html')


@app.route('/dashboard', methods=['GET', 'POST'])
@admin_login_required
def dashboard():
    admin_username = session.get('admin_username')
    num_customers = db.session.query(User).count()
    num_vehicles = db.session.query(Vehicle).count()
    num_admins = db.session.query(Admin).count()
    return render_template('admin/dashboard.html', admin_username=admin_username,
                           num_customers=num_customers, num_vehicles=num_vehicles, num_admins=num_admins)


@app.route('/manageCustomers', methods=['GET', 'POST'])
@admin_login_required
def MCustomers():
    admin_username = session.get('admin_username')

    query = db.session.query(User)
    if request.method == 'POST':
        full_name_filter = request.form.get('full_name_filter')
        username_filter = request.form.get('username_filter')
        email_filter = request.form.get('email_filter')
        phone_number_filter = request.form.get('phone_number_filter')

        if full_name_filter:
            query = query.filter(User.full_name.ilike(f"%{full_name_filter}%"))
        if username_filter:
            query = query.filter(User.username.ilike(f"%{username_filter}%"))
        if email_filter:
            query = query.filter(User.email.ilike(f"%{email_filter}%"))
        if phone_number_filter:
            query = query.filter(User.phone_number.ilike(f"%{phone_number_filter}%"))

    customers = query.all()

    return render_template('admin/manageCustomers.html', admin_username=admin_username, customers=customers)



@app.route('/manageVehicles', methods=['GET', 'POST'])
@admin_login_required
def MVehicles():
    admin_username = session.get('admin_username')
    vehicles = db.session.query(Vehicle).all()

    if request.method == 'POST':
        brand_filter = request.form.get('brand_filter')
        model_filter = request.form.get('model_filter')
        min_price_filter = request.form.get('min_price_filter')
        max_price_filter = request.form.get('max_price_filter')

        query = db.session.query(Vehicle)
        if brand_filter:
            query = query.filter(Vehicle.brand.ilike(f"%{brand_filter}%"))
        if model_filter:
            query = query.filter(Vehicle.model.ilike(f"%{model_filter}%"))
        if min_price_filter:
            query = query.filter(Vehicle.selling_price >= float(min_price_filter))
        if max_price_filter:
            query = query.filter(Vehicle.selling_price <= float(max_price_filter))

        vehicles = query.all()

    return render_template('admin/manageVehicles.html', admin_username=admin_username, vehicles=vehicles)

@app.route('/delete_vehicle/<int:id>', methods=['POST'])
@admin_login_required
def delete_vehicle(id):
    vehicle = db.session.query(Vehicle).get(id)
    if vehicle:
        db.session.delete(vehicle)
        db.session.commit()
        log_event('Delete Vehicle', f'Vehicle deleted: {vehicle.brand} {vehicle.model} by {session["admin_username"]}.')
    return redirect(url_for('MVehicles'))



@app.route('/logs', methods=['GET', 'POST'])
@admin_login_required
def admin_logs():
    admin_username = session.get('admin_username')
    logs = db.session.query(Log).all()
    return render_template('admin/logs.html', admin_username=admin_username, logs=logs)

@app.route('/admin_logout')
def admin_logout():
    if 'admin_logged_in' in session:
        admin_username = session.get('admin_username')
        session.pop('admin_logged_in', None)
        session.pop('admin_username', None)
        log_event('Logout', f'Successfully logged out Admin {admin_username}')
        session.clear()
        session.modified = True
        return redirect(url_for('admin_log_in'))
    else:
        return "Admin is not logged in."

if __name__ == '__main__':
    app.run(debug=True)

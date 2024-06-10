from flask import Flask, render_template, request, session, redirect, url_for, flash
from Forms import CreateUserForm, LoginForm, AdminLoginForm, CreateVehicleForm
import hashlib
from dotenv import load_dotenv, find_dotenv
import os
import model
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exists
# import mysql.connector
# db_2 = mysql.connector.connect(
#     host="localhost",
#     user="root",
#     password="EcoWheels123",
#     database="eco_wheels"
# )

from model import *

load_dotenv(find_dotenv())
db = SQLAlchemy()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URI")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")

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
        password_bytes = password.encode('utf-8')
        hashed_password = hashlib.sha256(password_bytes).hexdigest()
        confirm_password = create_user_form.confirm_password.data

        # Check if the user already exists (This is called IntegrityError)
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
            # Create a new user
            new_user = User(full_name=full_name, username=username, email=email, phone_number=phone_number,
                            password_hash=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            print("User created!")
            return redirect(url_for('login'))
    return render_template("customer/sign_up.html", form=create_user_form, error=error)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    login_form = LoginForm(request.form)
    if request.method == 'POST' and login_form.validate():
        email = login_form.email.data
        password = login_form.password.data
        password_bytes = password.encode('utf-8')
        entered_password_hash = hashlib.sha256(password_bytes).hexdigest()
        user = db.session.query(User).filter_by(email=email).first()

        if user and user.password_hash == entered_password_hash:
            session['user_id'] = user.id
            return redirect(url_for('home'))
        else:
            error = "Invalid email or password. Please try again."

    return render_template("customer/login.html", form=login_form, error=error)


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
@app.route('/admin_log_in', methods=['GET','POST'])
def admin_log_in():
    form = AdminLoginForm()
    if form.validate_on_submit():
        # Example: check username and password against stored credentials
        username = form.username.data
        password = form.password.data
        # Implement your authentication logic here
        if username == 'adminuser' and password == 'AdminPass1':  # Replace with your own logic
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Error in {getattr(form, field).label.text}: {error}", 'danger')
    return render_template('admin/admin_log_in.html', form=form)


@app.route('/createVehicle')
def createVehicle():
    return render_template('admin/createVehicleForm.html')


@app.route('/dashboard', methods=['GET','POST'])
def dashboard():
    return render_template('admin/dashboard.html')


@app.route('/manageCustomers')
def MCustomers():
    return render_template('admin/manageCustomers.html')


@app.route('/manageVehicles')
def MVehicles():
    return render_template('admin/manageVehicles.html')


if __name__ == '__main__':
    app.run(debug=True)

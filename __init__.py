from flask import Flask, render_template, request, redirect, url_for
from Forms import CreateUserForm
from werkzeug.security import generate_password_hash
import hashlib
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exists
import mysql.connector

app = Flask(__name__)
db = SQLAlchemy()
db_2 = mysql.connector.connect(
    host="localhost",
    user="root",
    password="EcoWheels123",
    database="eco_wheels"
)

def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://root:EcoWheels123@127.0.0.1:3306/eco_wheels"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = "mysecret"

    db.init_app(app)

    with app.app_context():
        db.create_all()  # Create sql tables if they don't already exist

    return app
app = create_app()
# def create_app():
#     app = Flask(__name__)
#     app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://JY:123456@127.0.0.1:3306/ASPJ"
#     app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
#     app.config["SECRET_KEY"] = "mysecret"
#
#     db.init_app(app)
#
#     with app.app_context():
#         import model
#         db.create_all()  # Create sql tables
#
#     return app

#JIAYINGG the following 4 lines of commented code is ursss! 
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://JY:123456@127.0.0.1:3306/ASPJ"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "mysecret"

db.init_app(app)

with app.app_context():
    import model

    db.create_all()


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
        password_hash = generate_password_hash(password)
        password_bytes = password.encode('utf-8')
        hashed_password = hashlib.sha256(password_bytes).hexdigest()
        confirm_password = create_user_form.confirm_password.data

        # Check if the user already exists (This is called IntegrityError)
        user_exists = db.session.query(exists().where(model.User.username == username)).scalar()
        email_exists = db.session.query(exists().where(model.User.email == email)).scalar()
        phone_number_exists = db.session.query(exists().where(model.User.phone_number == phone_number)).scalar()

        if user_exists:
            error = "User already exists!"
        # Check if the passwords match
            error = "Username already exists!"
        elif email_exists:
            error = "Email is already registered!"
        elif phone_number_exists:
            error = "Phone number is already registered!"
        elif password != confirm_password:
            error = "Passwords do not match!"
        else:
            # Create a new user
            new_user = model.User(full_name=full_name, username=username, email=email, phone_number=phone_number, password_hash=password_hash)
            new_user = model.User(full_name=full_name, username=username, email=email, phone_number=phone_number, password_hash=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            print("User created!")    
            return redirect(url_for('login'))
    return render_template("customer/sign_up.html", form=create_user_form, error=error)


@app.route('/test_sign_up')
def test_create_user():
    new_user = model.User(id=1, full_name="John Doe", username="johndoe", email="johndoe@gmail.com", phone_number="12345678", password_hash="password")
    db.session.add(new_user)
    db.session.commit()
    return "User created!"

@app.route('/login', methods=['GET', 'POST'])
def login():
    return render_template("customer/login.html")


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
        cursor = db_2.cursor()
        query = "INSERT INTO orders (fullname, email, address, city, state, zip_code, card_name, card_number, exp_month, exp_year, cvv) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
        values = (fullname, email, address, city, state, zip_code, card_name, card_number, exp_month, exp_year, cvv)
        cursor.execute(query, values)
        db_2.commit()
    except Exception as e:
        db_2.session.rollback()
        print("Failed to process payment:", e)  # Log the error or use a logging framework
        return "Error processing payment", 500
    return redirect(url_for('confirmation'))

@app.route('/view_payment')
def view_payment():
    cursor = db_2.cursor(dictionary=True)
    cursor.execute("SELECT * FROM orders")
    orders = cursor.fetchall()
    cursor.close()
    return render_template("admin/view_payment.html", orders=orders)


@app.route('/update_payment/<int:id>', methods=['GET', 'POST'])
def update_payment(id):
    if request.method == 'POST':
        fullname = request.form['fullname']
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

        cursor = db_2.cursor()
        cursor.execute("""
            UPDATE orders SET fullname=%s, email=%s, address=%s, city=%s, state=%s, zip_code=%s, card_name=%s, card_number=%s, exp_month=%s, exp_year=%s, cvv=%s
            WHERE order_id=%s
        """, (fullname, email, address, city, state, zip_code, card_name, card_number, exp_month, exp_year, cvv, id))
        db_2.commit()
        cursor.close()
        return redirect(url_for('view_payment'))
    else:
        cursor = db_2.cursor(dictionary=True)
        cursor.execute("SELECT * FROM orders WHERE order_id = %s", (id,))
        order = cursor.fetchone()
        cursor.close()
        return render_template('admin/update_payment.html', order=order)

@app.route('/delete_payment/<int:id>', methods=['POST'])
def delete_payment(id):
    cursor = db_2.cursor()
    cursor.execute("DELETE FROM orders WHERE order_id = %s", (id,))
    db_2.commit()
    cursor.close()
    return redirect(url_for('view_payment'))


# NEED TO METHOD = 'POST' THESE ADMIN PAGES
@app.route('/admin_log_in', methods=['GET', 'POST'])
def admin_log_in():
    # check whether input is correct with db
    return render_template('admin/admin_log_in.html')


@app.route('/createVehicle')
def createVehicle():
    return render_template('admin/createVehicleForm.html')


@app.route('/dashboard')
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

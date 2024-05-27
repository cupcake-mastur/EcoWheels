from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

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




@app.route('/')
def home():
    return render_template("homepage/homepage.html")


@app.route('/models')
def models():
    return render_template("homepage/models.html")


@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    return render_template("customer/sign_up.html")


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
        # your existing code
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print("Failed to process payment:", e)  # Log the error or use a logging framework
        return "Error processing payment", 500
    return redirect(url_for('confirmation'))


@app.route('/update_payment/<int:order_id>', methods=['GET', 'POST'])
def update_payment(order_id):
    from model import Order
    order = Order.query.get_or_404(order_id)
    if request.method == 'POST':
        # update fields
        order.fullname = request.form['fullname']
        order.email = request.form['email']
        order.address = request.form['address']
        order.city = request.form['city']
        order.state = request.form['state']
        order.zip_code = request.form['zip']
        order.card_name = request.form['cardname']
        order.card_number = request.form['cardnumber']
        order.exp_month = request.form['expmonth']
        order.exp_year = request.form['expyear']
        order.cvv = request.form['cvv']
        db.session.commit()
        return redirect(url_for('view_payment'))
    else:
        return render_template('admin/update_payment.html', order=order)
    
@app.route('/view_payment')
def view_payments():
    from model import Order  # Local import to avoid circular import issues
    orders = Order.query.all()  # Fetch all orders from the database
    return render_template('admin/view_payment.html', orders=orders)


@app.route('/delete_payment/<int:order_id>', methods=['POST'])
def delete_payment(order_id):
    from model import Order
    order = Order.query.get_or_404(order_id)
    db.session.delete(order)
    db.session.commit()
    return redirect(url_for('admin/view_payment.html'))



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

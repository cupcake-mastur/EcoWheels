from flask import Flask, render_template, request, redirect, url_for
import mysql.connector
app = Flask(__name__)

#paymentpage database
db = mysql.connector.connect(
    host="localhost",  
    user="root",  
    password="EcoWheels123",  
    database="eco_wheels"  
)

@app.route('/')
def home():
    return 'Hello world!'


@app.route('/sign_up')
def sign_up():
    return render_template("customer/sign_up.html")

@app.route('/payment')
def payment():
    return render_template("customer/payment.html")

@app.route('/process_payment', methods=['POST'])
def process_payment():
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

    cursor = db.cursor()
    query = "INSERT INTO orders (fullname, email, address, city, state, zip_code, card_name, card_number, exp_month, exp_year, cvv) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
    values = (fullname, email, address, city, state, zip_code, card_name, card_number, exp_month, exp_year, cvv)
    cursor.execute(query, values)
    db.commit()
    cursor.close()
    return redirect(url_for('confirmation'))


@app.route('/confirmation')
def confirmation():
    # Render a simple confirmation page
    return "Thank you for your order!"

@app.route('/view_payment')
def view_payment():
    cursor = db.cursor(dictionary=True)
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

        cursor = db.cursor()
        cursor.execute("""
            UPDATE orders SET fullname=%s, email=%s, address=%s, city=%s, state=%s, zip_code=%s, card_name=%s, card_number=%s, exp_month=%s, exp_year=%s, cvv=%s
            WHERE order_id=%s
        """, (fullname, email, address, city, state, zip_code, card_name, card_number, exp_month, exp_year, cvv, id))
        db.commit()
        cursor.close()
        return redirect(url_for('view_payment'))
    else:
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM orders WHERE order_id = %s", (id,))
        order = cursor.fetchone()
        cursor.close()
        return render_template('admin/update_payment.html', order=order)

@app.route('/delete_payment/<int:id>', methods=['POST'])
def delete_payment(id):
    cursor = db.cursor()
    cursor.execute("DELETE FROM orders WHERE order_id = %s", (id,))
    db.commit()
    cursor.close()
    return redirect(url_for('view_payment'))
   


# NEED TO METHOD = 'POST' THESE ADMIN PAGES
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

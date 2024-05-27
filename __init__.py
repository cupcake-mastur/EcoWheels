from flask import Flask, render_template, request, redirect, url_for
app = Flask(__name__)


@app.route('/')
def home():
    return render_template("homepage/homepage.html")
@app.route('/models')
def models():
    return render_template("homepage/models.html")

@app.route('/sign_up')
def sign_up():
    return render_template("customer/sign_up.html")

@app.route('/payment')
def payment():
    return render_template("customer/payment.html")

@app.route('/process_payment', methods=['POST'])
def process_payment():
    # Extract data from form submission
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
    return redirect(url_for('confirmation'))

@app.route('/confirmation')
def confirmation():
    # Render a simple confirmation page
    return "Thank you for your order!"


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

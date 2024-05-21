from flask import Flask, render_template, request, redirect, url_for
app = Flask(__name__)


@app.route('/')
def home():
    return 'Hello world!'


@app.route('/sign_up')
def sign_up():
    return render_template("customer/sign_up.html")


if __name__ == '__main__':
    app.run()

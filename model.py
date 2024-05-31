from flask_sqlalchemy import SQLAlchemy
from __init__ import db


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(64), nullable=False)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone_number = db.Column(db.String(8), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

    
class Order(db.Model):
    __tablename__ = 'orders'
    
    order_id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    address = db.Column(db.String(255), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(100), nullable=False)
    zip_code = db.Column(db.String(20), nullable=False)
    card_name = db.Column(db.String(255), nullable=False)
    card_number = db.Column(db.String(20), nullable=False)
    exp_month = db.Column(db.String(20), nullable=False)
    exp_year = db.Column(db.String(4), nullable=False)
    cvv = db.Column(db.String(5), nullable=False)
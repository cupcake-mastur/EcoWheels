from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Float, LargeBinary, Text
from werkzeug.security import generate_password_hash, check_password_hash

from __init__ import db


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(64), nullable=False)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone_number = db.Column(db.String(8), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    failed_attempts = db.Column(db.Integer, default=0)
    lockout_until = db.Column(db.DateTime, nullable=True)
    last_visited_url = db.Column(db.String(200), default='/')


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


class Admin(db.Model):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    # def set_password(self, password):
    #     # Update existing passwords using werkzeug.security
    #     self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Vehicle(db.Model):
    __tablename__ = 'vehicles'
    idvehicles = db.Column(db.Integer, primary_key=True, autoincrement=True)
    brand = db.Column(db.String(50), nullable=False)
    model = db.Column(db.String(50), nullable=False)
    selling_price = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(100), nullable=True)  # Adjusted to allow NULL values
    description = db.Column(db.Text, nullable=True)








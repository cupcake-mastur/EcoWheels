from decimal import Decimal
import pyotp
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Numeric, Float, LargeBinary, Text
from datetime import datetime, timedelta
import pytz
from werkzeug.security import generate_password_hash, check_password_hash


from __init__ import db
SGT = pytz.timezone('Asia/Singapore')


class Feedback(db.Model):
    __tablename__ = 'feedback'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    feedback = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Enum('good', 'moderate', 'bad', name='rating_enum'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    #timestamp = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f"<Feedback id={self.id} username={self.username} rating={self.rating}>"


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
    lockout_count = db.Column(db.Integer, default=0)
    password_history = db.relationship('PasswordHistory', backref='user', lazy=True)
    urls = db.relationship('UserURL', backref='user', lazy=True)
    password_reset_request = db.relationship('PasswordResetRequest', backref='user', lazy=True)


class UserURL(db.Model):
    __tablename__ = 'user_url'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    url = db.Column(db.String(200), nullable=False)
    visited_at = db.Column(db.DateTime, default=lambda: datetime.now(SGT))


class PasswordHistory(db.Model):
    __tablename__ = 'password_history'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    changed_at = db.Column(db.DateTime, default=lambda: datetime.now(SGT), nullable=False)


class PasswordResetRequest(db.Model):
    __tablename__ = 'password_reset_request'
    id = Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    email = db.Column(db.String(120), nullable=False)
    request_count = Column(db.Integer, default=0)
    last_request_time = Column(db.DateTime, default=lambda: datetime.now(SGT), nullable=False)

    def __init__(self, email, user_id=None):
        self.user_id = user_id
        self.email = email
        self.request_count = 0
        self.last_request_time = datetime.now(SGT)

    def can_request(self):
        now = datetime.now(SGT)
        
        if self.last_request_time.tzinfo is None:
            self.last_request_time = SGT.localize(self.last_request_time)
        
        if (now - self.last_request_time) > timedelta(seconds=40):
            self.request_count = 0  
            self.last_request_time = now  
            db.session.commit() 
        
        return self.request_count < 3
    
    def record_request(self):
        self.request_count += 1
        self.last_request_time = datetime.now(SGT)
        db.session.commit()


class Admin(db.Model):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    login_attempts = db.Column(db.Integer, default=0)
    is_suspended = db.Column(db.Boolean, default=False)
    totp_secret = db.Column(db.String(500), nullable=True)  # Add this field for TOTP secret
    is_first_login = db.Column(db.Boolean, default=True)  # Add this field to track first login

    # def set_password(self, password):
    #     # Update existing passwords using werkzeug.security
    #     self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Vehicle(db.Model):
    __tablename__ = 'vehicles'
    product_id = db.Column(db.String(50))
    idvehicles = db.Column(db.Integer, primary_key=True, autoincrement=True)
    brand = db.Column(db.String(50), nullable=False)
    model = db.Column(db.String(50), nullable=False)
    selling_price = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(100), nullable=True)  # Adjusted to allow NULL values
    description = db.Column(db.Text, nullable=True)
    stripe_link = db.Column(db.String(100), nullable=True)
    
class Product(db.Model):
    __tablename__ = 'PurchasedItem'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    prod_id = db.Column(db.String(255), unique=True, nullable=False)
    product_name = db.Column(db.String(255), nullable=True)
    full_name = db.Column(db.String(255), nullable=True)
    email = db.Column(db.String(255), nullable=True)
    price = db.Column(db.Numeric(10, 2), nullable=True)

    def __repr__(self):
        return f"<Product id={self.id} prod_id={self.prod_id} product_name={self.product_name}>"
    __tablename__ = 'PurchasedItem'

class Log(db.Model):
    __tablename__ = 'logs'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    event_type = db.Column(db.String(50), nullable=False)
    event_time = db.Column(db.DateTime, default=lambda: datetime.now(SGT), nullable=False)
    event_result = db.Column(db.String(255), nullable=False)
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import Form, EmailField, validators, PasswordField, StringField, IntegerField
from wtforms.fields.simple import SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, Regexp, NumberRange
import re


class CustomValidators:
    @staticmethod
    def validate_numeric(form, field):
        if field.data:
            if not re.match(r'^[0-9]+$', field.data):
                raise validators.ValidationError('Only numeric characters are allowed.')

class RequestPasswordResetForm(Form):
    email = EmailField('Email', [validators.DataRequired(), validators.Email(), validators.Length(max=50)])


class ResetPasswordForm(Form):
    password = PasswordField('New Password', [validators.DataRequired(), validators.length(min=8, max=30), 
                                          validators.Regexp(regex=re.compile(r'^(?=.*[!@#$%^&*(),.?":{}|<>])'))])
    confirm_password = PasswordField('Confirm New Password', [validators.DataRequired(), validators.length(min=8, max=30), 
                                          validators.Regexp(regex=re.compile(r'^(?=.*[!@#$%^&*(),.?":{}|<>])'))])


class CreateUserForm(Form):
    email = EmailField('Email', [validators.DataRequired(), validators.Email(), validators.Length(max=50)])
    full_name = StringField('Full Name', validators=[validators.DataRequired()])
    username = StringField('Username', validators=[validators.DataRequired()])
    phone_number = IntegerField('Phone Number', [validators.DataRequired(), validators.NumberRange(min=00000000, max=99999999)])
    password = PasswordField('Password', [validators.DataRequired(), validators.length(min=8, max=30), 
                                          validators.Regexp(regex=re.compile(r'^(?=.*[!@#$%^&*(),.?":{}|<>])'))])
    confirm_password = PasswordField('Confirm Password', [validators.DataRequired(), validators.length(min=8, max=30), 
                                          validators.Regexp(regex=re.compile(r'^(?=.*[!@#$%^&*(),.?":{}|<>])'))])


class LoginForm(Form):
    email = EmailField('Email', [validators.DataRequired(), validators.Email(), validators.Length(max=50)])
    password = PasswordField('Password', [validators.DataRequired(), validators.length(min=8, max=30), 
                                          validators.Regexp(regex=re.compile(r'^(?=.*[!@#$%^&*(),.?":{}|<>])'))])


class UpdateProfileForm(Form):
    email = EmailField('Email', [validators.DataRequired(), validators.Email(), validators.Length(max=50)])
    full_name = StringField('Full Name', validators=[validators.DataRequired()])
    username = StringField('Username', validators=[validators.DataRequired()])
    phone_number = IntegerField('Phone Number', [validators.DataRequired(),
                                                 validators.NumberRange(min=00000000, max=99999999)])
    current_password = PasswordField('', [validators.DataRequired(), validators.length(min=8, max=30)])
    new_password = PasswordField('New Password', [validators.Optional(), validators.length(min=8, max=30,
                                            message="New password must be between 8 and 30 characters long."), 
                                          validators.Regexp(regex=re.compile(r'^(?=.*[!@#$%^&*(),.?":{}|<>])'), 
                                                            message= "New password must contain at least one special character.")])
    confirm_new_password = PasswordField('Confirm New Password', [validators.Optional(), validators.length(min=8, max=30,
                                            message="New password must be between 8 and 30 characters long."), 
                                          validators.Regexp(regex=re.compile(r'^(?=.*[!@#$%^&*(),.?":{}|<>])'), 
                                                            message= "New password must contain at least one special character.")])

    card_name = StringField('Card Name', validators=[validators.Optional(), validators.length(max=30)])
    card_number = StringField('Card Number', validators=[
        validators.Optional(),
        validators.length(min=16, max=16),
        CustomValidators.validate_numeric
    ])
    exp_month = StringField('Expiry Month', validators=[
        validators.Optional(),
        validators.length(min=2, max=2),
        CustomValidators.validate_numeric
    ])
    exp_year = StringField('Expiry Year', validators=[
        validators.Optional(),
        validators.length(min=4, max=4),
        CustomValidators.validate_numeric
    ])
    cvv = StringField('CVV', validators=[
        validators.Optional(), 
        validators.length(min=3, max=3),
        CustomValidators.validate_numeric
    ])


class AdminLoginForm(FlaskForm):
    class Meta:
        csrf = True

    username = StringField('Username', validators=[
        DataRequired(message="Username is required."),
        Length(min=8, max=30, message="Username must be between 8 and 30 characters."),
        Regexp(
            r"^(?!.*['\"])[\w\d]{8,}$",
            message=("Username must contain at least 8 characters,"
                     "and cannot contain ', \" characters or special characters.")
        )
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required."),
        Regexp(
            r"^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?!.*['\x22]).{8,}$",
            message=("Password must contain at least 8 characters, including at least one number, "
                     "one uppercase letter, one lowercase letter, and cannot contain ', \" characters or special characters.")
        )
    ])
    submit = SubmitField('Continue')


class CreateVehicleForm(FlaskForm):
    brand = StringField('Brand', validators=[
        DataRequired(message="Brand is required."),
        Regexp(r'^[A-Za-z\s]+$', message="Brand can only contain alphabetic characters and spaces.")
    ])
    model = StringField('Model', validators=[
        DataRequired(message="Model is required."),
        Length(min=2, max=30, message="Model must be between 2 and 30 characters."),
        Regexp(r'^[A-Za-z0-9\s]+$', message="Model can only contain alphanumeric characters and spaces.")
    ])
    price = IntegerField('Selling Price in SGD ($)', validators=[
        DataRequired(message="Price is required."),
        NumberRange(min=0, message="Price must be a positive number.")
    ])
    file = FileField('Image', validators=[
        FileRequired(message="Image is required."),
        FileAllowed(['jpg', 'jpeg', 'png'], message="Only image files are allowed (jpg, jpeg, png).")
    ])

    description = TextAreaField('Description', validators=[
        DataRequired(message="Description is required."),
        Length(min=30, max=500, message="Description must be between 30 and 500 characters."),
        Regexp(r'^[\w\s.,!?"/-]+$',
               message="Description can only contain letters, numbers, spaces, and basic punctuation including hyphens, single quotes, double quotes, and slashes.")
    ])
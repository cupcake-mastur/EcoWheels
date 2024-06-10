from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import Form, EmailField, validators, PasswordField, StringField, IntegerField
from wtforms.fields.simple import SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, Regexp, NumberRange


class CreateUserForm(Form):
    email = EmailField('Email', [validators.DataRequired(), validators.Email()])
    full_name = StringField('Full Name', validators=[validators.DataRequired()])
    username = StringField('Username', validators=[validators.DataRequired()])
    phone_number = IntegerField('Phone Number', [validators.DataRequired(),
                                                 validators.NumberRange(min=00000000, max=99999999)])
    password = PasswordField('Password', [validators.DataRequired(), validators.length(min=8, max=30)])
    confirm_password = PasswordField('Confirm Password', [validators.DataRequired(), validators.length(min=8, max=30)])


class LoginForm(Form):
    email = EmailField('Email', [validators.DataRequired(), validators.Email()])
    password = PasswordField('Password', [validators.DataRequired(), validators.length(min=8, max=30)])


class AdminLoginForm(FlaskForm):
    class Meta:
        csrf = True

    username = StringField('Username', validators=[
        DataRequired(message="Username is required."),
        Length(min=8, max=30, message="Username must be between 8 and 30 characters.")
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
    file = FileField('Image', validators=[DataRequired(message="Image is required.")])

    description = TextAreaField('Description', validators=[
        DataRequired(message="Description is required."),
        Length(min=30, max=500, message="Description must be between 30 and 500 characters.")
    ])
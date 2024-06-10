from flask_wtf import FlaskForm
from wtforms import Form, EmailField, validators, PasswordField, StringField, IntegerField
from wtforms.fields.simple import SubmitField
from wtforms.validators import DataRequired, Length, Regexp


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
                     "one uppercase letter, one lowercase letter, and cannot contain ' or \" characters.")
        )
    ])
    submit = SubmitField('Continue')
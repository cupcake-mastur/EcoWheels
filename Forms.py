from wtforms import Form, validators
from wtforms.fields import PasswordField,StringField, IntegerField 


class CreateUserForm(Form):
    email = StringField('Email', [validators.DataRequired(), validators.Email()])
    full_name = StringField('Full Name', validators=[validators.DataRequired()])
    username = StringField('Username', validators=[validators.DataRequired()])
    phone_number = IntegerField('Phone Number', [validators.DataRequired(),
                                                 validators.NumberRange(min=00000000, max=99999999)])
    password = PasswordField('Password', [validators.DataRequired(), validators.length(min=8, max=30)])
    confirm_password = PasswordField('Confirm Password', [validators.DataRequired(), validators.length(min=8, max=30)])


class LoginForm(Form):
    email = StringField('Email', [validators.DataRequired(), validators.Email()])
    password = PasswordField('Password', [validators.DataRequired(), validators.length(min=8, max=30)])
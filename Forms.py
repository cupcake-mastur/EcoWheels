from wtforms import Form, EmailField, validators, PasswordField, StringField, IntegerField


def no_special_characters(Form, field):
    special_characters = "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?"
    if any(char in special_characters for char in field.data):
        raise validators.ValidationError("Special characters are not allowed.")


class CreateUserForm(Form):
    email = EmailField('Email', [validators.DataRequired(), validators.Email()])
    full_name = StringField('Full Name', validators=[validators.DataRequired(), no_special_characters])
    username = StringField('Username', validators=[validators.DataRequired(), no_special_characters])
    phone_number = IntegerField('Phone Number', [validators.DataRequired(), validators.NumberRange(min=00000000, max=99999999)])
    password = PasswordField('Password', [validators.DataRequired(), validators.length(min=8, max=30)])
    confirm_password = PasswordField('Confirm Password', [validators.DataRequired(), validators.length(min=8, max=30)])

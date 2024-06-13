from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, RadioField
from wtforms.validators import DataRequired

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    captcha = StringField('Captcha', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

class DistanceForm(FlaskForm):
    distance = RadioField('Distance', choices=[('1', '1 km'), ('2', '2 km'), ('3', '3 km'), ('4', '4 km'), ('5', '5 km')], validators=[DataRequired()])
    submit = SubmitField('Submit Distance')

class VerifyForm(FlaskForm):
    qr_code = StringField('QR Code', validators=[DataRequired()])
    submit = SubmitField('Verify')

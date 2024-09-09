from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, FloatField, DateField, IntegerField,EmailField
from wtforms.validators import DataRequired, Length, Regexp, InputRequired, Email
# from flask_ckeditor import CKEditorField

class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    re_password = PasswordField("Re-Enter Password", validators=[DataRequired()])
    name = StringField("Username", validators=[DataRequired()])
    submit = SubmitField("Sign Me Up!")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Let Me In!")

class OTPForm(FlaskForm):
    email = EmailField('Email', validators=[InputRequired(), Email()])
    otp = IntegerField('OTP', validators=[InputRequired()])
    submit = SubmitField('Verify OTP')

class FraudDetectionForm(FlaskForm):
    date = DateField('Date', format='%Y-%m-%d', validators=[DataRequired()])
    account_id = StringField('Account ID', validators=[
        DataRequired(),
        Length(min=12, max=12, message="Account ID must be exactly 12 digits."),
        Regexp(r'^\d{12}$', message="Account ID must consist of digits only.")])
    day = StringField("Day of Week", validators=[DataRequired()])
    time = StringField("Time", validators=[DataRequired()])
    card_type = StringField("Type of Card", validators=[DataRequired()])
    entry_mode = StringField("Entry Mode", validators=[DataRequired()])
    amount = FloatField("Amount", validators=[DataRequired()])
    transaction_type = StringField("Type of Transaction", validators=[DataRequired()])
    merchant_group = StringField("Merchant Group", validators=[DataRequired()])
    country = StringField("Country of Transaction", validators=[DataRequired()])
    residence = StringField("Country of Residence", validators=[DataRequired()])
    bank = StringField("Bank", validators=[DataRequired()])
    submit = SubmitField("Submit for Prediction")



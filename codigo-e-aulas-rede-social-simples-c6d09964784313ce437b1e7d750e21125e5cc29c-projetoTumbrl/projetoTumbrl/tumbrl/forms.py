# Aqui vão estar os formulários do nosso site

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, HiddenField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError

from tumbrl.models import User
from wtforms.widgets import TextArea


class FormLogin(FlaskForm):
    email = StringField('Email')
    password = PasswordField('Password')
    btn = SubmitField('Login')


class FormCreateNewAccount(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(6, 25)])
    checkPassword = PasswordField('Check Password', validators=[DataRequired(), Length(6, 25), EqualTo('password')])
    btn = SubmitField('Create Account')

    def validate_email(self, email):
        email_of_user = User.query.filter_by(email=email.data).first()
        if email_of_user:
            return ValidationError('~ email já existe ~')


class FormCreateNewPost(FlaskForm):
    text = StringField('PostText', widget=TextArea(), validators=[DataRequired()])
    photo = FileField('Photo', validators=[DataRequired()])
    btn = SubmitField('Publish')
    post_id = HiddenField()

class FormDeleteAccount(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password_confirm = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    confirm = SubmitField('Confirm Deletion')  

class FormChangePassword(FlaskForm):
    email = StringField('E-mail', validators=[DataRequired(), Email()])
    current_password = PasswordField('Senha Atual', validators=[DataRequired()])
    new_password = PasswordField('Nova Senha', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirme a Nova Senha', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Alterar Senha')

class DeletePostForm(FlaskForm):
    post_id = HiddenField('Post ID')
    submit = SubmitField('Excluir Post')


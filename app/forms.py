from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Optional
from flask_login import current_user
from app.models import User

class RegistrationForm(FlaskForm):
    username = StringField('Username', 
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is already taken. Please choose a different one.')
            
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already registered. Please use a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

# In app/forms.py
class HideDataForm(FlaskForm):
    media_file = FileField('Select Media File', 
                         validators=[FileRequired(), 
                                    FileAllowed(['jpg', 'jpeg', 'png', 'bmp', 'gif', 'wav', 'mp3', 'mp4', 'avi', 'mov'], 
                                               'Only image, audio or video files are allowed!')])
    message = TextAreaField('Message to Hide', validators=[DataRequired()])
    encryption = BooleanField('Use Encryption', default=True)
    encryption_type = SelectField('Encryption Type', 
                                 choices=[
                                     ('aes', 'AES (Password)'), 
                                     ('aes_rsa', 'AES+RSA (Hybrid)'),
                                     ('caesar', 'Caesar Cipher (Classical)'),
                                     ('vigenere', 'Vigenère Cipher (Classical)')
                                 ],
                                 default='aes')
    
    # Modified to make it required for classical ciphers
    classical_key = StringField('Cipher Key (for classical ciphers)')
    
    password = PasswordField('Password (for encryption)')
    integrity_check = BooleanField('Add Integrity Check', default=True)
    submit = SubmitField('Hide Data')
    
    def validate_password(self, password):
        if self.encryption.data and self.encryption_type.data in ['aes', 'aes_rsa'] and not password.data:
            raise ValidationError('Password is required for AES encryption.')
            
    def validate_classical_key(self, classical_key):
        if self.encryption.data and self.encryption_type.data in ['caesar', 'playfair', 'vigenere', 'hill'] and not classical_key.data:
            raise ValidationError('Cipher key is required for classical cipher encryption.')

class ExtractDataForm(FlaskForm):
    stego_file = FileField('Select Stego File', 
                         validators=[FileRequired(), 
                                    FileAllowed(['jpg', 'jpeg', 'png', 'bmp', 'gif', 'wav', 'mp3', 'mp4', 'avi', 'mov'], 
                                               'Only image, audio or video files are allowed!')])
    frame_info = FileField('Frame Info File (for video)', 
                         validators=[FileAllowed(['info'], 'Only .info files are allowed!')])
    is_encrypted = BooleanField('Message is Encrypted', default=True)
    encryption_type = SelectField('Encryption Type', 
                                 choices=[
                                     ('aes', 'AES (Password)'), 
                                     ('aes_rsa', 'AES+RSA (Hybrid)'),
                                     ('caesar', 'Caesar Cipher (Classical)'),
                                     ('vigenere', 'Vigenère Cipher (Classical)')
                                 ],
                                 default='aes')
    # Now used for classical ciphers
    classical_key = StringField('Cipher Key (for classical ciphers)')
    password = PasswordField('Password (for decryption)')
    submit = SubmitField('Extract Data')
    
    def validate_password(self, password):
        if self.is_encrypted.data and self.encryption_type.data in ['aes', 'aes_rsa'] and not password.data:
            raise ValidationError('Password is required for AES decryption.')
            
    def validate_classical_key(self, classical_key):
        if self.is_encrypted.data and self.encryption_type.data in ['caesar', 'playfair', 'vigenere', 'hill'] and not classical_key.data:
            raise ValidationError('Cipher key is required for classical cipher decryption.')
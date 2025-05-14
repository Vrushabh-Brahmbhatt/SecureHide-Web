from datetime import datetime
from flask_login import UserMixin
from app import db, login_manager

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    date_joined = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    stego_files = db.relationship('StegoFile', backref='owner', lazy=True)
    
    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

class StegoFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    original_filename = db.Column(db.String(100), nullable=True)
    file_path = db.Column(db.String(255), nullable=False)
    media_type = db.Column(db.String(20), nullable=False)  # image, audio, video
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    has_message = db.Column(db.Boolean, default=False)
    is_encrypted = db.Column(db.Boolean, default=False)
    has_integrity_check = db.Column(db.Boolean, default=False)
    additional_info = db.Column(db.String(255), nullable=True)  # For video frame info etc.
    
    # Remove these lines:
    # is_metadata = db.Column(db.Boolean, default=False)
    # parent_file_id = db.Column(db.Integer, db.ForeignKey('stego_file.id'), nullable=True)
    # metadata_files = db.relationship('StegoFile', backref=db.backref('parent_file', remote_side=[id]), cascade='all, delete-orphan')
    
    # Foreign Keys
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    def __repr__(self):
        return f"StegoFile('{self.filename}', '{self.media_type}')"
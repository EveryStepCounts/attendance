from init import db
from sqlalchemy import func
from datetime import datetime
import pytz

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    checkin_count = db.Column(db.Integer, default=0)
    total_distance = db.Column(db.Float, default=0.0)
    is_active = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    checkins = db.relationship('Checkin', backref='user', lazy=True)

class Checkin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(pytz.timezone('Asia/Shanghai')).replace(microsecond=0))
    distance = db.Column(db.Float, nullable=False)
    verified = db.Column(db.Boolean, default=False)
    verified_by = db.Column(db.String(50), nullable=True)

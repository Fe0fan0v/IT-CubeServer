from datetime import datetime
from .db import db


class User(db.Document):
    public_id = db.StringField(required=True, unique=True)
    email = db.StringField(required=True, unique=True)
    password = db.StringField(required=True, unique=True)
    role = db.StringField(default='entrant')
    validated = db.BooleanField(default=False)
    registration_date = db.DateTimeField(default=datetime.utcnow)
    name = db.StringField()
    surname = db.StringField()
    courses = db.ListField()
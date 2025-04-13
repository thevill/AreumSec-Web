# models.py
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class DNSBL(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)

    def __repr__(self):
        return f'<DNSBL {self.name}>'
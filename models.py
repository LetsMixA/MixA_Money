from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class PendingMint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner = db.Column(db.String(42), nullable=False)
    ipfs_hash = db.Column(db.String(64), nullable=False)
    metadata_url = db.Column(db.String(150), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending') # pending, verified, failed, minted
    verification_attempts = db.Column(db.Integer, default=0)

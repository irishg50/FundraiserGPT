from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    prompt = db.Column(db.Text, nullable=False)
    engine = db.Column(db.String(50), nullable=False)
    response = db.Column(db.Text, nullable=False)
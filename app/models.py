from app import db
from werkzeug.security import generate_password_hash, check_password_hash
import random, string
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired

secret_random_key = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(32))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True, unique=True)
    email = db.Column(db.String(150), index=True, unique=True)
    password_hash = db.Column(db.String(128))

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_auth_token(self, expiration=60):
        s = Serializer(secret_random_key, expires_in = expiration)
        return s.dumps({'id': self.id })

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(secret_random_key)
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None
        except BadSignature:
            return None
        user_id = data['id']
        return user_id

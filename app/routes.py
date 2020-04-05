from app import app, db
from flask import jsonify, request
from app.models import User

@app.route('/user', methods=['GET'])
def get_all_users():
    users = User.query.all()
    output = []
    
    for user in users:
        user_data = {}
        user_data['username'] = user.username
        user_data['email'] = user.email
        output.append(user_data)

    return jsonify({'list': output}), 200

@app.route('/user', methods=['POST'])
def create_user():
    username = request.get_json()['username']
    email = request.get_json()['email']
    password = request.get_json()['password'] 
    if username is None or email is None or password is None:
        return jsonify({'error':'incorrect'}), 400

    user_by_username = User.query.filter_by(username=username).first()
    user_by_email = User.query.filter_by(email=email).first()
    if user_by_username is not None or user_by_email is not None:
        return jsonify({'error':'user already exists'}), 200

    new_user = User(username=username, email=email)
    new_user.set_password(password)

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'registered successfully'})


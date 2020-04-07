from app import app, db
from flask import jsonify, request, g,render_template
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
import httplib2
import requests
from app.models import User
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth

basic_auth = HTTPBasicAuth()
token_auth = HTTPTokenAuth()

@basic_auth.verify_password
def verify_password(username, password):
    auth = request.authorization

    if auth is None or auth.username is None or auth.password is None:
        error()
    else:
        user = User.query.filter_by(username = username).first()
        if not user or not user.check_password(password):
            return False
    
    g.user = user
    return True

@token_auth.verify_token
def verify_token(token):
    user_id = User.verify_auth_token(token)
    g.user = User.query.filter_by(id = user_id).one() if user_id else None
    return g.user is not None

@basic_auth.error_handler
def error():
    return jsonify({'error': 'unauthorized'}), 401

@app.route('/token', methods=['POST'])
@basic_auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})

@app.route('/oauth/<provider>', methods=['POST'])
def login_oauth(provider):
    if provider == 'google':
        auth_code = request.data.decode("utf-8")
    
        try:
            oauth_flow = flow_from_clientsecrets('client_secret.json', scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(auth_code)
        except FlowExchangeError:
            return jsonify({'Failed to upgrade the authorization code.'}), 401
    
        userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
        params = {'access_token': credentials.access_token, 'alt':'json'}
        answer = requests.get(userinfo_url, params=params)
        
        data = answer.json()
        name = data['name']
        picture = data['picture']
        email = data['email']
        
        user_by_username = User.query.filter_by(username=name).first()
        user_by_email = User.query.filter_by(email=email).first()
        if user_by_username is not None or user_by_email is not None:
            return jsonify({'error':'user already exists'}), 200
        new_user = User(username=name, email=email)
        new_user.set_password('password')
        db.session.add(new_user)
        db.session.commit()
        
        token = new_user.generate_auth_token()
        
        return jsonify({'token': token.decode('ascii')})
    else:
        return 'Unrecognized Provider'

@app.route('/user', methods=['GET'])
@token_auth.login_required
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

@app.route('/clientOAuth')
def start():
    return render_template('clientOAuth.html')
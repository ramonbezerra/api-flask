from app import app
from flask import jsonify

@app.route('/test', methods=['GET'])
def test_route():
    return jsonify({'resource': 'OK'}), 200
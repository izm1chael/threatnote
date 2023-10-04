from  main import app
from  main import db
from  models import User, Indicators, Links
import logging

from flask import request, redirect, jsonify 
from flask_login import current_user, login_user
from werkzeug.security import check_password_hash
from itsdangerous.url_safe import URLSafeTimedSerializer as Serializer

import traceback
import json

#set to false if no authentication
AUTHENTICATE_API_CALLS=True

TOKEN_EXPIRATION = 60*60

'''
User can authenticate using basic authentication, 
passing email and password through query parameters, 
passing email and password through posted json, 
passing a token through query parameters
passing a token through hrough posted json

Returns a User object if authenticated
'''
def authenticate_credentials(request):
    api_key = None
    
    if current_user.is_authenticated:
        id = current_user.get_id()
        user = User.query.get(id)
        return user
    else:
        if request.authorization:
            api_key = request.authorization.get('api_key')
        elif 'api_key' in request.form:
            api_key = request.form.get('api_key')
        elif 'api_key' in request.args:
            api_key = request.args.get('api_key')
        elif request.get_json():
            data = request.get_json()
            api_key = data.get('api_key')
        
        if api_key:
            user = User.query.filter_by(tn_api_key=api_key).first()
            if user:
                # Log a message indicating successful authentication
                app.logger.info(f"User authenticated with API key: {api_key}")
                return user
    
    # Log a message indicating authentication failure
    app.logger.warning("Authentication failed.")
    return None

'''
This returns a list of indicators
Args-
(optional)report_id - only indicators linked to a certain report
(optional) email and password - if  AUTHENTICATE_API_CALLS set to true and not using basic authentication
(optional) token - if  AUTHENTICATE_API_CALLS set to true and not using basic authentication
'''
@app.route('/api/indicators/<indicator_id>', methods=['GET'])
def api_indicator_get(indicator_id):
    try:
        user = None
        if AUTHENTICATE_API_CALLS:
            user = authenticate_credentials(request)
        if user or not AUTHENTICATE_API_CALLS:
            try:
                indicator = db.session.query(Indicators).filter(Indicators.id == int(indicator_id)).first()
            except ValueError:
                indicator = db.session.query(Indicators).filter(Indicators.indicator == indicator_id).first()

            if indicator:
                indicator_dict = indicator.__dict__
                indicator_dict.pop('_sa_instance_state')
            else:
                indicator_dict = {}
            return jsonify(indicator_dict)

        # Log a message indicating unauthorized access
        app.logger.warning("Unauthorized access to the API")

        resp = jsonify({'message': 'unauthorized'})
        resp.status_code = 401
        return resp

    except Exception as err:
        tb = traceback.format_exc()
        # Log the exception for debugging
        app.logger.error(f"An error occurred: {err}\n{tb}")
        resp = jsonify({'message': 'An error occurred', 'error': str(err)})
        resp.status_code = 503
        return resp


'''
This returns a single indicator
Args-
indcator_id - indicator_id or indicator name- can use either
(optional) email and password - if  AUTHENTICATE_API_CALLS set to true and not using basic authentication
(optional) token - if  AUTHENTICATE_API_CALLS set to true and not using basic authentication
'''
@app.route('/api/login', methods=['GET', 'POST'])
def api_get_token():
    try:
        user = authenticate_credentials(request)
        if user:
            s = Serializer(app.config['SECRET_KEY'], expires_in=TOKEN_EXPIRATION)
            token = s.dumps({'id': user.id})
            return jsonify({'token': token.decode('ascii'), 'expires_in': TOKEN_EXPIRATION})

        # Log a message indicating unauthorized access
        app.logger.warning("Unauthorized access to the API login endpoint")

        resp = jsonify({'message': 'unauthorized'})
        resp.status_code = 401
        return resp

    except Exception as err:
        tb = traceback.format_exc()
        # Log the exception for debugging
        app.logger.error(f"An error occurred: {err}\n{tb}")
        resp = jsonify({'message': 'An error occurred', 'error': str(err)})
        resp.status_code = 503
        return resp
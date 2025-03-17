import os
from flask import redirect, session, url_for, request, jsonify
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
import json

SCOPES = ['https://www.googleapis.com/auth/calendar']
CLIENT_SECRETS_FILE = os.path.join(os.path.dirname(__file__), 'credentials.json')

def create_flow(redirect_uri=None):
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=redirect_uri or request.base_url + '/oauth2callback'
    )
    return flow

def credentials_to_dict(credentials):
    return{
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token.uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

def get_credentials():
    if 'credentials' not in session:
        return None
    credentials = Credentials(**session['credentials'])
    if credentials.expired and credentials.refresh_token:
        request = Request()
        credentials.refresh(request)
    return credentials

def dict_to_credentials(cred_dict):
    return Credentials(
        token=cred_dict.get('token'),
        refresh_token=cred_dict.get('refresh_token'),
        token_uri=cred_dict.get('token_uri'),
        client_id=cred_dict.get('client_id'),
        client_secret=cred_dict.get('client_secret'),
        scopes=cred_dict.get('scopes')
    )

def setup_auth_routes(app):
    @app.route('/login')
    def login():
        flow = create_flow(redirect_uri=url_for('oauth2callback', _external=True))
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true'
            prompt='consent'
        )
        # Store state in session
        session['state'] = state

        #create flow instance
        flow = session.get('state', None)
        
        #Set state in flow
        flow.state = state

        #Exchange authorization code for tokens
        authorization_response = request.url
        flow.fetch_token(authorization_response=request.url) 

        #get credentials from flow
        credentials = flow.credentials

        #Store credentials in session 
        session['credentials'] = credentials_to_dict(credentials)
        
        #Redirect to index page
        return redirect(authorization_url)
    
    @app.route('/logout')
    def logout():
        # Clear the session
        if 'credentials' in session:
            del session['credentials']
            del session['state']
        return jsonify({'message': 'Logged out successfully'}), 200

    @app.route('/check-auth')
    def check_auth():
        # Check if credentials are in session
        if 'credentials' in session:
            #Check if tokens are valid
            credentials_dict = session['credentials']
            try:
                credentials = dict_to_credentials(credentials_dict)
                if credentials.expired:
                    credentials.refresh(Request())
                    session['credentials'] = credentials_to_dict(credentials)
                return jsonify({'authenticated': True}), 200
            except Exception as e:
                print(f"Authentication error: {str(e)}")
                return jsonify({'authenticated': False}), 401
        else:
            return jsonify({'authenticated': False}), 401
        
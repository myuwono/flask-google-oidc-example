# Python standard libraries
import json
import os
import re
import jwt
from datetime import datetime, timedelta
from logging.config import dictConfig

# Third-party libraries
from flask import Flask, redirect, request, url_for, jsonify, make_response
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
    UserMixin
)


from flask_caching import Cache
from oauthlib.oauth2 import WebApplicationClient
from oauthlib.oauth2.rfc6749.errors import InvalidGrantError
import requests

# Configuration
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", None)
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", None)
SERVER_BASE_URL = os.environ.get("SERVER_BASE_URL", None)

if GOOGLE_CLIENT_ID is None:
    raise RuntimeError("GOOGLE_CLIENT_ID must be specified")

if GOOGLE_CLIENT_SECRET is None:
    raise RuntimeError("GOOGLE_CLIENT_SECRET must be specified")

if SERVER_BASE_URL is None:
    raise RuntimeError("SERVER_BASE_URL must be specified")

GOOGLE_CALLBACK_URL = f"{SERVER_BASE_URL}/login/callback"
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", os.urandom(24)) 


from logging.config import dictConfig
dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
})

# Flask app setup
app = Flask(__name__)

app.secret_key = os.urandom(24)

# User session management setup
# https://flask-login.readthedocs.io/en/latest
login_manager = LoginManager()
login_manager.init_app(app)

# OAuth 2 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)

user_store = Cache(config={'CACHE_TYPE': 'SimpleCache', 'CACHE_DEFAULT_TIMEOUT': 24 * 3600})
user_store.init_app(app)

token_store = Cache(config={'CACHE_TYPE': 'SimpleCache', 'CACHE_DEFAULT_TIMEOUT': 3600})
token_store.init_app(app)

class User(UserMixin):
    def __init__(self, user_id, email, name) -> None:
        self.id = user_id
        self.email = email
        self.name = name

class Token():
    def __init__(self, user_id, access_token, expires_at) -> None:
        self.access_token = access_token
        self.expires_at = expires_at
        self.user_id = user_id


@login_manager.user_loader
def load_user(user_id):
    return user_store.get(user_id)


@login_manager.request_loader
def request_loader(request):
    authorization_header = request.headers.get('Authorization')
    if authorization_header is None:
        return

    match_output = re.search('^Bearer (.*)$', authorization_header)
    if match_output is None:
        return

    bearer_token = match_output.group(1)

    access_token = token_store.get(bearer_token)
    
    if access_token is None:
        return

    if datetime.now() >= access_token.expires_at:
        token_store.delete(access_token)
        return
    
    user = user_store.get(access_token.user_id)

    if user is None:
        return
    
    return user

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

@app.route("/")
def index():
    if current_user.is_authenticated:
        return (
            "<p>Hello, {}! You're logged in! Email: {}</p>"
            '<a class="button" href="/logout">Logout</a>'.format(
                current_user.name, current_user.email
            )
        )
    else:
        return redirect(url_for('login'))

@app.route("/login")
def login():
    # Find out what URL to hit for Google login
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for Google login and provide
    # scopes that let you retrieve user's profile from Google
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=GOOGLE_CALLBACK_URL,
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)

def encode_auth_token(user_id):
    payload = {
        'exp': datetime.now() + timedelta(days=0, seconds=3600),
        'iat': datetime.now(),
        'sub': user_id
    }
    return jwt.encode(
        payload,
        app.secret_key,
        algorithm='HS256'
    )

@app.route("/login/callback")
def callback():
    # Get authorization code Google sent back to you
    code = request.args.get("code")
    # Find out what URL to hit to get tokens that allow you to ask for
    # things on behalf of a user
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

        # Prepare and send a request to get tokens! Yay tokens!
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=f"{GOOGLE_CALLBACK_URL}?{request.query_string.decode()}",
        redirect_url=GOOGLE_CALLBACK_URL,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    access_token = json.dumps(token_response.json())
    # Parse the tokens

    try:
        access_token_parsed = client.parse_request_body_response(access_token)

        # # Now that you have tokens (yay) let's find and hit the URL
        # # from Google that gives you the user's profile information,
        # # including their Google profile image and email
        userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
        uri, headers, body = client.add_token(userinfo_endpoint)
        userinfo_response = requests.get(uri, headers=headers, data=body)

        userinfo = userinfo_response.json()
        
        if userinfo["email_verified"] != True:
            return "unverivied user", 403

        expires_at = datetime.fromtimestamp(access_token_parsed["expires_at"])
        user_context_token = encode_auth_token(userinfo["sub"])
        
        user = User(userinfo["sub"], userinfo["email"], userinfo["name"])
        token = Token(userinfo["sub"], access_token_parsed["access_token"], expires_at)
        user_store.set(user.id, user)
        token_store.set(user_context_token, token)
        login_user(user)

        resp = {
            "token": user_context_token
        }

        app.logger.info("user logged in: %s", json.dumps(user.__dict__))

        return make_response(jsonify(resp), 200)
    except InvalidGrantError as err:
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    logout_user()
    return 'Logged out'

@login_manager.unauthorized_handler
def unauthorized_handler():
    return make_response(jsonify({"error_code": "unauthorized", "description": "missing or invalid login credentials"}), 401)

@app.route('/api/v1/test')
@login_required
def protected(): 
    return make_response(jsonify({
        "google_id": current_user.id,
        "email": current_user.email,
        "name": current_user.name
    }), 200)


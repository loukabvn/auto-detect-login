#!/usr/bin/python3

from flask import Flask, request, session, redirect, url_for, render_template, flash
from flask_httpauth import HTTPBasicAuth, HTTPDigestAuth, HTTPTokenAuth
from datetime import datetime, timedelta
from base64 import b64decode, b64encode
from functools import wraps
import random
import pytz
import jwt


# Flask config
app = Flask(__name__)

app.config.update(
    DEBUG=True,
    SECRET_KEY="secret"
)

################################################################################
###             Constants, templates variables and helpers                   ###
################################################################################

PROTECTED_AREA = "You're in protected area"
ACCESS_DENIED  = "Access denied"
LOGIN_SUCCESS  = "Login success"
LOGIN_FAILED   = "Login failed"
LOGGED         = "is_logged"

CSRF_TOKEN_SIZE = 32

DEF_LOGIN_TEMPLATE = "login.html"
CSRF_LOGIN_TEMPLATE    = "csrf_login.html"
DEF_CSRF_TOKEN_NAME    = "csrf_token"
USER_FIELD = "username"
PWD_FIELD  = "password"

# Login page render helper
def render_login(action, template=DEF_LOGIN_TEMPLATE, title="Login page", **kwargs):
    return render_template(
        template,
        user_field=USER_FIELD, pwd_field=PWD_FIELD,
        action=action, title=title,
        **kwargs
    )

# Default credentials
USERS = {
    'root': 'toor',
    'admin': 'admin'
}

def check_creds(username: str, password: str) -> bool:
    return username in USERS and USERS.get(username) == password

def check_request_creds(request) -> bool:
    username = request.form[USER_FIELD]
    password = request.form[PWD_FIELD]
    return check_creds(username, password)

# Login required decorator
def session_login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if session.get(LOGGED):
            return f(*args, **kwargs)
        else:
            return redirect(request.url.replace('protected', 'login'))
    return wrap

################################################################################
###                             Home page                                    ###
################################################################################

@app.route('/')
def home():
    return render_template("index.html")

################################################################################
###                             basic_auth_login                             ###
################################################################################

basic_auth = HTTPBasicAuth()

@basic_auth.verify_password
def verify_password(username, password):
    return check_creds(username, password)

@app.route('/basic_auth/protected')
@basic_auth.login_required
def basic_auth_protected():
    return PROTECTED_AREA

################################################################################
###                             csrf_auth_login                              ###
################################################################################

@app.route('/csrf_auth/login', methods=['GET', 'POST'])
def csrf_auth_login():
    # POST
    if request.method == "POST":
        stored_token = session.get(DEF_CSRF_TOKEN_NAME)
        received_token = request.form[DEF_CSRF_TOKEN_NAME]
        session.clear()
        if check_request_creds(request) and stored_token == received_token:
            session[LOGGED] = True
            return LOGIN_SUCCESS
        else:
            return LOGIN_FAILED, 401
    # GET
    token = b64encode(random.randbytes(CSRF_TOKEN_SIZE)).decode()
    session[DEF_CSRF_TOKEN_NAME] = token
    return render_login(request.path,
        template=CSRF_LOGIN_TEMPLATE, csrf_token_name=DEF_CSRF_TOKEN_NAME,
        csrf_token=token)

@app.route('/csrf_auth/protected')
@session_login_required
def csrf_auth_protected():
    return PROTECTED_AREA

################################################################################
###                           default_auth_login                             ###
################################################################################

@app.route('/default_auth/login', methods=['GET', 'POST'])
def default_auth_login():
    # POST method
    if request.method == "POST":
        if check_request_creds(request):
            session[LOGGED] = True
            return LOGIN_SUCCESS
        else:
            return LOGIN_FAILED, 401
    # GET method
    return render_login(request.path, title="Default login page")

@app.route('/default_auth/protected')
@session_login_required
def default_auth_protected():
    return PROTECTED_AREA

################################################################################
###                           digest_auth_login                             ###
################################################################################

digest_auth = HTTPDigestAuth()

@digest_auth.get_password
def get_password(username):
    return users.get(username)

@app.route('/digest_auth/protected')
@digest_auth.login_required
def digest_auth_protected():
    return PROTECTED_AREA

################################################################################
###                             jwt_auth_login                               ###
################################################################################

# JWT helper
def create_jwt(username):
    timezone = pytz.timezone("Europe/Paris")
    payload = {
        "username": username,
        "iat": timezone.localize(datetime.now()),
        "exp": timezone.localize(datetime.now() + timedelta(hours=1))
    }
    return jwt.encode(payload, app.secret_key, algorithm="HS256")

token_auth = HTTPTokenAuth()

@token_auth.verify_token
def verify_token(token):
    try:
        r = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        return r
    except:
        return False

@app.route('/jwt_auth/login', methods=['GET', 'POST'])
def jwt_auth_login():
    # POST method
    if request.method == "POST":
        if check_request_creds(request):
            token = create_jwt(request.form[USER_FIELD])
            return f"Access token: {token}"
        else:
            return LOGIN_FAILED, 401
    # GET method
    return render_login(request.path, title="JWT login page")

@app.route('/jwt_auth/protected')
@token_auth.login_required
def jwt_auth_protected():
    return PROTECTED_AREA

################################################################################
###                           proxy_auth_login                               ###
################################################################################

proxy_auth = HTTPBasicAuth()
proxy_auth.header = "Proxy-Authorization"

@proxy_auth.verify_password
def verify_password(username, password):
    return check_creds(username, password)

@app.route('/proxy_auth/protected')
@proxy_auth.login_required
def proxy_auth_protected():
    return PROTECTED_AREA

################################################################################
###                               Logout                                     ###
################################################################################

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


### Entry point ###

if __name__ == "__main__":
    app.run()

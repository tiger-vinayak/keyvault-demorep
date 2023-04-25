import os
from config import get_secret
from flask import (Flask, redirect, render_template, request,
                   send_from_directory, url_for)
import jwt
import hmac
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import requests
from functools import wraps
import datetime
import base64

app = Flask(__name__)


def get_secret(name):
    credential = DefaultAzureCredential()
    secret_client = SecretClient(vault_url="https://keyvaultdemo51.vault.azure.net/", credential=credential)
    secret = secret_client.get_secret(name)
    print(secret.name)
    print(secret.value)
    return secret.value
  

client_id = get_secret("CLIENTid")
client_secret = get_secret("CLIENTsecret")
tenant_id = get_secret("TENANTid")


secret_key_hex = b'simpel_portal_secret_key'
digest = hmac.new(secret_key_hex, digestmod='sha256').digest()
jwt_secret_key = base64.urlsafe_b64encode(digest).rstrip().decode('utf-8')
scope = ["User.ReadBasic.All"]
rediredt_end_uri = "loginredirect"
redirect_path = "/loginredirect"




def login_required(check):
    """
    This decorator will check whether the user is logged in or not.
    If the user is logged in, it will check whether the jwt is expired
    or not. If the jwt is expired it will redirect to login.
    """
    @wraps(check)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get('jwt_token')
        if not token:
            return redirect('/login')
        try:
            jwt_data = jwt.decode(token, jwt_secret_key, algorithms=['HS256'])
            exp_time = datetime.datetime.fromtimestamp(jwt_data['exp'])
            if datetime.datetime.utcnow() > exp_time:
                print("Time Remaining:\t",(datetime.datetime.utcnow()-exp_time))
                return redirect('/login')
        except jwt.ExpiredSignatureError:
            return redirect('/login')
        except jwt.InvalidTokenError:
            return redirect('/login')
        return check(*args, **kwargs)

    return decorated_function

@app.route('/login', methods=['GET'])
def login():
    """
    This route will redirect the user to login page.
    """
    test_check_get_secret = get_secret("demoSECRET")
    print("Test_key_Vault:\t",test_check_get_secret)
    root_url = request.url_root
    # redirect_uri = f'{root_url}{rediredt_end_uri}'
    redirect_uri = get_secret("REDIRECTuri")
#     if redirect_uri.find('localhost'):
#         redirect_uri_updated  = redirect_uri.replace("/loginredirect",":80/loginredirect")

#     else:
#         redirect_uri_updated = redirect_uri
#     # Redirect user to Microsoft login page
    print("Redirect URI in Login", redirect_uri)
    auth_url = (
                    f"https://login.microsoftonline.com/"
                    f"{tenant_id}/oauth2/v2.0/authorize?"
                    f"client_id={client_id}"
                    f"&redirect_uri={redirect_uri}"
                    f"&response_type=code"
                    f"&scope={' '.join(scope)}"
                    f"&response_mode=query"
               )

    return redirect(auth_url)

@app.route(redirect_path, methods=['GET'])
def login_callback():
    """
    This route will redirect to the callback url which will help the 
    user to logged in. It will create a jwt token and store it as a 
    cookie in the browser.
    """
    # Handle Microsoft login callback and exchange authorization code for access token
    code = request.args.get('code')
    root_url = request.url_root
    # redirect_uri = f'{root_url}{rediredt_end_uri}'
    redirect_uri = get_secret("REDIRECTuri")
#     if redirect_uri.find('localhost'):
#         redirect_uri_updated  = redirect_uri.replace("/loginredirect",":80/loginredirect")

#     else:
#         redirect_uri_updated = redirect_uri

    print("Redirect URI in Callback", redirect_uri)
    if code:
        token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'
        token_payload = {
            'client_id': client_id,
            'client_secret': client_secret,
            'code': code,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code',
            'scope': ' '.join(scope)
        }
        token_response = requests.post(token_url, data=token_payload, timeout=(3.05, 27))
        token_data = token_response.json()
        if 'access_token' in token_data:
            access_token = token_data['access_token']
            expiration = datetime.datetime.now() + datetime.timedelta(hours=24)
            jwt_token = jwt.encode(
                                    {
                                        'access_token': access_token, 
                                        'exp': expiration
                                    }, jwt_secret_key, algorithm='HS256')
            response = redirect('/')
            response.set_cookie('jwt_token', jwt_token, secure=True)
            return response

    return 'Login failed'

@app.route('/logout', methods=['GET'])
def logout():
    """
    This route will clear the cookie stored in the browser and
    will redirect to login route.
    """
    response = redirect('/login')
    response.delete_cookie('jwt_token')
    return response


# -------------------------------------------------------------------------
@app.route('/')
@login_required
def index():
   print('Request for index page received')
   return render_template('index.html')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/hello', methods=['POST'])
def hello():
   name = request.form.get('name')

   if name:
       print('Request for hello page received with name=%s' % name)
       print(type(name))
       secret = get_secret("demoSECRET")
       return render_template('hello.html', name = name, secret=secret)
   else:
       print('Request for hello page received with no name or blank name -- redirecting')
       return redirect(url_for('index'))


if __name__ == '__main__':
   app.run()

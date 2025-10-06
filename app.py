# Requirements
# * pip install flask
# * pip install google-cloud-secret-manager
# * pip install Authlib
# * pip install python-dotenv

from flask import Flask, render_template, jsonify, request, url_for, session, redirect, make_response
from werkzeug.utils import secure_filename
import requests
from dotenv import load_dotenv
from google.cloud import secretmanager
import os
import json
from authlib.integrations.flask_client import OAuth # type: ignore
import google.auth
import threading
from datetime import datetime
from flask_talisman import Talisman

# * This is use to make the google authentication callback work
# * Without this, the google authentication will not work after deploying in cloud run
from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv()

app = Flask(__name__)



# csp = {
#     'default-src': ['\'self\''],
#     'style-src': [
#         '\'self\'',
#         'https://cdn.jsdelivr.net',    
#         'https://cdnjs.cloudflare.com', 
#         '\'unsafe-inline\'',           
#     ],
#     'script-src': [
#         '\'self\'',
#         'https://cdn.jsdelivr.net',
#         'https://cdnjs.cloudflare.com',
#         '\'unsafe-inline\'',           
#         '\'unsafe-eval\'',             
#     ],
#     'font-src': [
#         '\'self\'',
#         'https://fonts.gstatic.com',
#         'https://cdn.jsdelivr.net'
#     ]
# }

# Talisman(app, content_security_policy=csp)


# @app.after_request
# def add_security_headers(response):
#     response.headers['X-Frame-Options'] = 'SAMEORIGIN'
#     response.headers['X-Content-Type-Options'] = 'nosniff'
#     response.headers['X-XSS-Protection'] = '1; mode=block'
#     response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'

#     # ✅ Updated CSP to allow styles, scripts, fonts, images
#     response.headers['Content-Security-Policy'] = (
#         "default-src 'self'; "
#         "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
#         "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
#         "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
#         "img-src 'self' data: https://cdn.jsdelivr.net; "
#     )

#     response.headers['Referrer-Policy'] = 'no-referrer-when-downgrade'
#     response.headers['Permissions-Policy'] = 'geolocation=(), microphone=()'
#     return response

# @app.errorhandler(404)
# @app.errorhandler(500)
# def error_handler(e):
#     response = make_response("Error", e.code if hasattr(e, 'code') else 500)
#     return add_security_headers(response)

Talisman(app,
    content_security_policy={
        'default-src': ["'self'"],
        'style-src': ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net', 'https://fonts.googleapis.com'],
        'script-src': ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net'],
        'font-src': ["'self'", 'https://fonts.gstatic.com', 'https://cdn.jsdelivr.net'],
        'img-src': ["'self'", 'data:', 'https://cdn.jsdelivr.net'],
    },
    frame_options='SAMEORIGIN',
    referrer_policy='no-referrer-when-downgrade',
    permissions_policy={
        "geolocation": "()",
        "microphone": "()"
    },
    force_https=True  # Required for HSTS
)


app.secret_key = 'your_secret_key'

app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

secret_project_id = os.getenv('EP_PROJECT_ID')
secret_id = os.getenv('SECRET_ID')


domain = "https://cash-non-cash-api-latest-740032229271.europe-west1.run.app"

# domain = "http://127.0.0.1:5001" # TODO: Change this to prod before deploying


def get_api_key(project_id: str, secret_id: str) -> str:
    client = secretmanager.SecretManagerServiceClient()
    secret_name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"
    response = client.access_secret_version(name=secret_name)
    return response.payload.data.decode("UTF-8")

api_key = get_api_key(project_id=secret_project_id, secret_id=secret_id)


def get_oauth_config_from_secret(project_id: str, secret_id: str) -> dict:
    secret_client = secretmanager.SecretManagerServiceClient()
    secret_name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"

    response = secret_client.access_secret_version(
        request={"name": secret_name})
    secret_payload = response.payload.data.decode("UTF-8")

    oauth_config = json.loads(secret_payload)
    return oauth_config


oauth_secrets = get_oauth_config_from_secret(
    os.getenv('EP_PROJECT_ID'), "cash-non-cash-google-oauth")

client_id = oauth_secrets["GOOGLE_CLIENT_ID"]
client_secret = oauth_secrets["GOOGLE_CLIENT_SECRET"]
redirect_uri = oauth_secrets["GOOGLE_REDIRECT_URI"]

print(f"Client ID: {client_id}")
print(f"Client Secret: {client_secret}")
print(f"Redirect URI: {redirect_uri}")

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=client_id,
    client_secret=client_secret,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    },
    redirect_uri=redirect_uri,
)

# @app.route('/open_folder')
# def open_folder():
#     return redirect(f'https://drive.google.com/drive/folders/{session.get('user')}')

@app.route('/login')
def login():
    redirect_uri = url_for('callback', _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route('/callback')
def callback():
    token = google.authorize_access_token()
    user_info = google.get(
        'https://openidconnect.googleapis.com/v1/userinfo').json()
    session['user'] = user_info
    session['active_account'] = user_info.get('email')
    print(session['active_account'])
    # print(user_info)
    return redirect('/')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/')
def index():
    try:
        if 'user' in session and session['user']:
            user_account = session.get('user')
            full_name = user_account['name']
            email = user_account['email']
            
            # *---------------------------------------------------------------------
            # TODO: Add additional validation. Create user master in BQ instead
            # ! Cons: This will need a UI for user management
            # ? This only allows primer emails
            
            domain = email.split("@")[1]
            if not domain == "primergrp.com":
                print("Not valid primer email")
                return render_template('noaccess.html', email=email)
            else:
                print("Valid primer email")
            # *----------------------------------------------------------------------
            
            picture = user_account['picture']
            return render_template('index.html', full_name=full_name, email=email, picture=picture)
        else:
            return render_template('login.html')
    except Exception as e:
        print(f"Error: {e}")
    
    
@app.route('/dashboard')
def dashboard():
    if 'user' in session and session['user']:
        user_account = session.get('user')
        full_name = user_account['name']
        email = user_account['email']
        
        # *---------------------------------------------------------------------
        # TODO: Add additional validation. Create user master in BQ instead
        # ! Cons: This will need a UI for user management
        # ? This only allows primer emails
        
        domain = email.split("@")[1]
        if not domain == "primergrp.com":
            print("Not valid primer email")
            return render_template('noaccess.html', email=email)
        else:
            print("Valid primer email")
        # *----------------------------------------------------------------------
        print(get_master_data(email))
        picture = user_account['picture']
        return render_template('dashboard.html', full_name=full_name, email=email, picture=picture, master_data=get_master_data(email))
    else:
        return render_template('login.html')

# Upload with IR start <---------------------------------------------------------------------------------------------///////
@app.route('/api_upload_ir', methods=['POST'])
def api_upload_ir():
    try:
        file = request.files.get('ir_file')
        ir_type = request.form.get('ir_type')
        ir_description = request.form.get('ir_description')
        uploaded_by = session.get('active_account')

        if not file:
            return jsonify({'error': 'No file provided'}), 400

        file.stream.seek(0)
        response_msg = upload_file(file, ir_type, ir_description, uploaded_by)

        if response_msg['status'] == "success":
            file.stream.seek(0)
            send_to_doc_ai(file)
            return jsonify({"message":"File uploaded successfully.",
                            "status":"success"}), 200
        else:
            return jsonify({"message":"File was failed to upload.",
                            "status":"failed"}), 500

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


def upload_file(file, ir_type, ir_description, uploaded_by):
    try:
        url = f"{domain}/upload_ir"

        payload = {
            "ir_type": ir_type,
            "ir_description": ir_description,
            "uploaded_by": uploaded_by
        }

        files = {
            'file': (secure_filename(file.filename), file.stream, file.content_type)
        }

        headers = {
            'X-API-KEY': api_key
        }

        response = requests.post(
            url, files=files, headers=headers, data=payload)

        if response.status_code == 200:
            print("File upload success")
            return {"status":"success"}
        else:
            print("File upload failed")
            return {"status":"failed"}

    except Exception as e:
        return jsonify({"status": "failed"}), 500
# Upload with IR end <----------------------------------------------------------------------------------------------////////

# NEW API FOR BULK UPLOAD
@app.route('/api_upload_bulk', methods=['POST'])
def api_upload_bulk():
    try:
        url = f"{domain}/upload_bulk_to_gdrive"
        
        print("Starting bulk upload.")
        file_list = request.files.getlist('bulk_file')
        uploaded_by = session.get('active_account')
    
        if not file_list:
            return jsonify({'error': 'No files provided'}), 400
        
        payload = {
            "uploaded_by": uploaded_by
        }

        files = [
            ("bulk_file", (f.filename, f, f.mimetype))
            for f in file_list
        ]
        
        headers = {
            'X-API-KEY': api_key
        }

        response = requests.post(url, data=payload, files=files, headers=headers)
        
        print(f"API Response: {response.status_code} - {response.text}")
        
        if response.status_code == 200: 
            return {"status": "success"}
        else:
            return {"status": "failed", "details": response.text}
        
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


# Send to gemini api start <----------------------------------------------------------------------------------------////////
def send_to_doc_ai(file):
    try:
        print("Gemini processing has started")
        api_url = "https://us-west1-pgc-dma-dev-sandbox.cloudfunctions.net/cash-non-cash-gemini-test"

        file.stream.seek(0)

        files = {
            'file': (
                secure_filename(file.filename),
                file.stream,
                file.content_type
            )
        }
        
        response = requests.post(api_url, files=files)

        if response.status_code == 200:
            print(f"Status Code: {response.status_code}")

            doc_type = response.json().get('document_type')

            print(doc_type)

            if doc_type in ("CASH","NON-CASH"):
                processing_status = "success"
            else:
                processing_status = "failed"
                
            print(f"Gemini processing is {processing_status}")
            return {"status": processing_status}
        else:
            print(f"Gemini processing failed with status {response.status_code}")
            return {"status": "failed"}

    except Exception as e:
        print(f"Send to DOC AI Error: {e}")
        return {"status":"failed","message":f"{str(e)}"}
# Send to gemini api end <--------------------------------------------------------------------------------------------////////


def get_master_data(user):
    try:
        StartDate = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print(f"User: {user}")

        url = f"{domain}/get_app_master_data"

        headers = {
            'X-API-KEY': api_key,
            'Content-Type': 'application/json'
        }

        payload = {
            "user": user
        }

        response = requests.post(url, json=payload, headers=headers)

        if response.status_code != 200:
            print(
                f"Error getting master data: {response.status_code} - {response.text}")
            return False

        app_master_list = response.json()

        if not app_master_list:
            print("No application master data found.")
            return False

        master_details = app_master_list

        return master_details

    except Exception as e:
        return False

if __name__ == '__main__':
    app.run(debug=True)

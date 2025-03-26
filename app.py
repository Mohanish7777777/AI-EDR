from flask import Flask, request, jsonify, render_template, redirect, url_for
import threading  # Add this line to import the threading module
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import google.generativeai as genai
import os
import requests
from datetime import datetime
from pymongo import MongoClient
from bson import ObjectId
import bcrypt

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this to a secure secret key

# Configure MongoDB
client = MongoClient('mongodb+srv://myAtlasDBUser:jobijobi123@ai-edr.abwzp.mongodb.net')
db = client.malware_detection
users_collection = db.users
detections_collection = db.detections

# Default admin credentials (CHANGE THESE BEFORE PRODUCTION!)
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "SecurePassword123!"  # Change this to a strong password

# Initialize default admin if none exists
if users_collection.count_documents({"is_admin": True}) == 0:
    hashed_password = bcrypt.hashpw(DEFAULT_ADMIN_PASSWORD.encode('utf-8'), bcrypt.gensalt())
    users_collection.insert_one({
        'username': DEFAULT_ADMIN_USERNAME,
        'password': hashed_password,
        'is_admin': True,
        'created_at': datetime.now()
    })
    print(f"Created default admin user: {DEFAULT_ADMIN_USERNAME}/{DEFAULT_ADMIN_PASSWORD}")

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, user_data):
        self.user_data = user_data

    def get_id(self):
        return str(self.user_data['_id'])

@login_manager.user_loader
def load_user(user_id):
    user_data = users_collection.find_one({'_id': ObjectId(user_id)})
    return User(user_data) if user_data else None

# Configure Gemini API
genai.configure(api_key="AIzaSyDTGMCstnO007h0o5wxlNzpmT-Ulq_lQWk")
model = genai.GenerativeModel('gemini-2.0-flash-exp')
TINES_WEBHOOK_URL = "https://cool-river-6431.tines.com/webhook/e62673882ea8b0e03563ca9b167c769e/63e263e2f06addd487d9f18a606292a5"
    
@app.route('/', methods=['GET', 'POST'])
def index():
    return "Welcome to the AI-EDR System!"

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        
        user = users_collection.find_one({'username': username})
        if user and bcrypt.checkpw(password, user['password']):
            user_obj = User(user)
            login_user(user_obj)
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    detections = list(detections_collection.find().sort('timestamp', -1))
    return render_template('dashboard.html', detections=detections)

@app.route('/detection/<detection_id>')
@login_required
def detection_details(detection_id):
    detection = detections_collection.find_one({'_id': ObjectId(detection_id)})
    return render_template('detection_details.html', detection=detection)

@app.route('/add_admin', methods=['GET', 'POST'])
@login_required
def add_admin():
    if not current_user.user_data.get('is_admin'):
        return "Unauthorized", 403
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        hashed = bcrypt.hashpw(password, bcrypt.gensalt())
        
        users_collection.insert_one({
            'username': username,
            'password': hashed,
            'is_admin': True
        })
        return redirect(url_for('dashboard'))
    
    return render_template('add_admin.html')

def analyze_report(report):
    """Analyzes the malicious report and extracts relevant information."""

    event = report.get("detect", {}).get("event", {})
    routing = report.get("detect", {}).get("routing", {})
    detect_mtd = report.get("detect_mtd", {})

    malicious_info = {
        "file_path": event.get("FILE_PATH", "N/A"),
        "command_line": event.get("COMMAND_LINE", "N/A"),
        "hash": event.get("HASH", "N/A"),
        "memory_usage": event.get("MEMORY_USAGE", "N/A"),
        "file_signed": "Yes" if event.get("FILE_IS_SIGNED") else "No",
        "parent_pid": event.get("PARENT_PROCESS_ID", "N/A"),
        "process_id": event.get("PROCESS_ID", "N/A"),
        "user_name": event.get("USER_NAME", "N/A"),
        "event_time": routing.get("event_time", "N/A"),
        "event_id": routing.get("event_id", "N/A"),
        "hostname": routing.get("hostname", "N/A"),
        "int_ip": routing.get("int_ip", "N/A"),
        "ext_ip": routing.get("ext_ip", "N/A"),
        "priority_level": detect_mtd.get("level", "N/A"),
        "description": detect_mtd.get("description", "N/A"),
        "tags": detect_mtd.get("tags", []),
        "false_positives": detect_mtd.get("falsepositives", []),
        "link": report.get("link", "N/A"),
    }

    startpoint_info = {
        "parent_file_path": event.get("PARENT", {}).get("FILE_PATH", "N/A"),
        "parent_command_line": event.get("PARENT", {}).get("COMMAND_LINE", "N/A"),
        "parent_hash": event.get("PARENT", {}).get("HASH", "N/A"),
        "parent_pid": event.get("PARENT", {}).get("PROCESS_ID", "N/A"),
        "parent_username": event.get("PARENT", {}).get("USER_NAME", "N/A"),
    }

    return malicious_info, startpoint_info

def generate_solution_steps(report):
    """Generates solution steps using Gemini API."""
    malicious_info, startpoint_info = analyze_report(report)
    prompt = f"""
    Given the following malware analysis report, provide detailed solution steps to mitigate the threat:

    Malicious File Path: {malicious_info['file_path']}
    Command Line: {malicious_info['command_line']}
    Process ID: {malicious_info['process_id']}
    Parent Process ID: {malicious_info['parent_pid']}
    Priority Level: {malicious_info['priority_level']}
    Description: {malicious_info['description']}
    Tags: {malicious_info['tags']}
    Parent File Path: {startpoint_info['parent_file_path']}
    Parent Command Line: {startpoint_info['parent_command_line']}
    Parent PID: {startpoint_info['parent_pid']}
    """
    try:
        response = model.generate_content(prompt)
        return response.text.split('\n')
    except Exception as e:
        return [f"Error generating solution steps: {e}"]

def trigger_tines_webhook(sid, decision):
    """Triggers the Tines webhook."""
    try:
        data = {
            "sid": sid,
            "decision": decision
        }
        response = requests.post(TINES_WEBHOOK_URL, json=data)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        print(f"Tines webhook triggered successfully: {TINES_WEBHOOK_URL}, with data: {data}")
    except requests.exceptions.RequestException as e:
        print(f"Error triggering Tines webhook: {TINES_WEBHOOK_URL}, {e}")

@app.route('/analyze', methods=['POST', 'GET'])
def analyze():
    if request.method == 'POST':
        try:
            report = request.get_json()
            # Start the analysis in a background thread
            threading.Thread(target=analyze_background, args=(report,)).start()

            return jsonify({'message': 'Analysis is being processed in the background.'}), 202
        except Exception as e:
            return jsonify({'error': str(e)}), 400
    else:
        return render_template('form.html')

def analyze_background(report):
    """Function to handle the analysis in the background."""
    malicious_info, startpoint_info = analyze_report(report)
    solution_steps = generate_solution_steps(report)

    # Store detection in MongoDB
    detection_data = {
        "timestamp": datetime.now(),
        "malicious_info": malicious_info,
        "startpoint_info": startpoint_info,
        "solution_steps": solution_steps,
        "raw_report": report,
        "reviewed": False,
        "admin_comments": ""
    }
    detections_collection.insert_one(detection_data)

    # Tines Webhook Trigger
    sid = report.get("routing", {}).get("sid", "UNKNOWN_SID")
    priority_level = malicious_info['priority_level'].lower()

    if priority_level in ['high', 'medium']:
        trigger_tines_webhook(sid, "YES")
    else:
        trigger_tines_webhook(sid, "NO")


# Add route for admin review
@app.route('/review/<detection_id>', methods=['POST'])
@login_required
def review_detection(detection_id):
    if not current_user.user_data.get('is_admin'):
        return "Unauthorized", 403
    
    comments = request.form['comments']
    detections_collection.update_one(
        {'_id': ObjectId(detection_id)},
        {'$set': {'reviewed': True, 'admin_comments': comments}}
    )
    return redirect(url_for('detection_details', detection_id=detection_id))

if __name__ == '__main__':
    app.run(debug=True)

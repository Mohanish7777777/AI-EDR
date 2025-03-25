# Configure MongoDB
client = MongoClient('mongodb+srv://myAtlasDBUser:jobijobi123@ai-edr.abwzp.mongodb.net/?retryWrites=true&w=majority')
db = client.malware_detection
users_collection = db.users
detections_collection = db.detections

# Default admin credentials (change before production!)
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "changeme123!"  # Change this!

# Create default admin if none exists
if not users_collection.find_one({"is_admin": True}):
    hashed = bcrypt.hashpw(DEFAULT_ADMIN_PASSWORD.encode('utf-8'), bcrypt.gensalt())
    users_collection.insert_one({
        'username': DEFAULT_ADMIN_USERNAME,
        'password': hashed,
        'is_admin': True
    })
    print(f"Created default admin user: {DEFAULT_ADMIN_USERNAME}/{DEFAULT_ADMIN_PASSWORD}")

# Configure Flask-Login
login_manager = LoginManager()
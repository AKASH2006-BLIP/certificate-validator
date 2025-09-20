import os
from flask import Flask, request, jsonify, redirect, url_for
from pymongo import MongoClient
import easyocr
from hashlib import sha256
from dotenv import load_dotenv
from flask_admin import Admin
from flask_admin.contrib.pymongo import ModelView
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import io

# Load environment variables
load_dotenv()

app = Flask(__name__, static_folder="../frontend", static_url_path="/")
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")

# --- Database Connection ---
client = None
db = None
certificates_collection = None
users_collection = None

try:
    mongo_uri = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
    db = client.get_database("certificate-validator-db")
    certificates_collection = db.get_collection("certificates")
    users_collection = db.get_collection("users")
    # Test connection
    client.admin.command('ping')
    print("Successfully connected to MongoDB!")
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")
    print("Running in offline mode - database features will be limited")

# --- Flask-Login Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_login'

class User(UserMixin):
    def __init__(self, email):
        self.email = email
    
    def get_id(self):
        return str(self.email)

@login_manager.user_loader
def load_user(email):
    if users_collection is not None:
        try:
            user_data = users_collection.find_one({"email": email})
            if user_data:
                return User(email=user_data['email'])
        except Exception as e:
            print(f"Error loading user: {e}")
    return None

# --- Flask-Admin Setup ---
admin = Admin(app, name='Admin Dashboard', template_mode='bootstrap3', url='/admin')

class ProtectedAdminView(ModelView):
    column_list = ('_id', 'student_name', 'roll_number', 'institution_id', 'degree', 'examination_year', 'certificate_number')
    
    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('admin_login'))

# Add the admin view only if database is connected
if certificates_collection is not None:
    try:
        admin.add_view(ProtectedAdminView(certificates_collection, name='Certificates'))
    except Exception as e:
        print(f"Error adding admin view: {e}")

# --- OCR and Validation Logic ---
reader = None
try:
    reader = easyocr.Reader(['en'], gpu=False)
    print("EasyOCR initialized successfully!")
except Exception as e:
    print(f"Error initializing EasyOCR: {e}")
    print("OCR functionality will be limited")

def get_hash(data):
    return sha256(data.encode('utf-8')).hexdigest()

@app.route('/api/verify', methods=['POST'])
def verify_certificate():
    if reader is None:
        return jsonify({"message": "OCR service not available"}), 503
    
    if certificates_collection is None:
        return jsonify({"message": "Database not available"}), 503
    
    if 'file' not in request.files:
        return jsonify({"message": "No file part"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"message": "No selected file"}), 400

    try:
        # Reset file pointer to beginning
        file.seek(0)
        file_data = file.read()
        
        # Use BytesIO for OCR
        image_bytes = io.BytesIO(file_data)
        results = reader.readtext(image_bytes.getvalue())
        extracted_text = " ".join([text[1] for text in results])
        
        if not extracted_text.strip():
            return jsonify({"status": "Invalid", "message": "No text could be extracted from the image."}), 200
        
    except Exception as e:
        return jsonify({"message": f"OCR failed: {str(e)}"}), 500

    try:
        # Search for partial matches in extracted text
        search_terms = extracted_text.lower().split()
        match_found = None
        
        # Try to find certificate by student name, roll number, or certificate number
        for term in search_terms:
            if len(term) > 3:  # Only search for meaningful terms
                # Search by student name
                match = certificates_collection.find_one({
                    "$or": [
                        {"student_name": {"$regex": term, "$options": "i"}},
                        {"roll_number": {"$regex": term, "$options": "i"}},
                        {"certificate_number": {"$regex": term, "$options": "i"}},
                        {"extracted_text": {"$regex": term, "$options": "i"}}
                    ]
                })
                if match:
                    match_found = match
                    break

        if match_found:
            stored_hash = match_found.get('hash')
            current_hash = get_hash(extracted_text)
            
            if stored_hash == current_hash:
                return jsonify({
                    "status": "Authentic", 
                    "message": "Certificate validated successfully.", 
                    "details": {
                        "student_name": match_found.get('student_name', 'N/A'),
                        "roll_number": match_found.get('roll_number', 'N/A'),
                        "institution_id": match_found.get('institution_id', 'N/A'),
                        "degree": match_found.get('degree', 'N/A'),
                        "examination_year": match_found.get('examination_year', 'N/A'),
                        "certificate_number": match_found.get('certificate_number', 'N/A'),
                        "college": match_found.get('college', 'N/A')
                    }
                }), 200
            else:
                return jsonify({"status": "Forged", "message": "Certificate data has been tampered with."}), 200
        else:
            return jsonify({"status": "Invalid", "message": "Certificate not found in our records."}), 200
    
    except Exception as e:
        return jsonify({"message": f"Database error: {str(e)}"}), 500

# --- Routes for serving static files ---
@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.route('/admin/login.html')
def admin_login_page():
    if current_user.is_authenticated:
        return redirect(url_for('admin.index'))
    return app.send_static_file('index.html')

# --- Admin Authentication Routes ---
@app.route('/admin_login', methods=['POST'])
def admin_login():
    if users_collection is None:
        return "Database not available", 503
    
    if current_user.is_authenticated:
        return redirect(url_for('admin.index'))
    
    email = request.form.get('email')
    password = request.form.get('password')
    
    if not email or not password:
        return "Email and password are required", 400
    
    try:
        user_data = users_collection.find_one({"email": email})

        if user_data and check_password_hash(user_data['password_hash'], password):
            user = User(email=user_data['email'])
            login_user(user)
            return redirect(url_for('admin.index'))
        else:
            return "Invalid credentials. Please go back and try again.", 401
    
    except Exception as e:
        return f"Login error: {str(e)}", 500

@app.route('/admin_logout')
@login_required
def admin_logout():
    logout_user()
    return redirect(url_for('index'))

# --- Error Handlers ---
@app.errorhandler(404)
def not_found(error):
    return jsonify({"message": "Resource not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"message": "Internal server error"}), 500

# --- Initialize Demo Data ---
def initialize_demo_data():
    if users_collection is None:
        print("No database connection - skipping demo data initialization")
        return
    
    try:
        # Create demo admin user if it doesn't exist
        existing_user = users_collection.find_one({"email": "admin@jharkhand.gov.in"})
        if existing_user is None:
            users_collection.insert_one({
                "username": "Admin",
                "email": "admin@jharkhand.gov.in",
                "password_hash": generate_password_hash("admin123")
            })
            print("Demo admin user created.")
        else:
            print("Admin user already exists.")
        
        # Create demo certificates based on your actual Kolhan University certificate
        if certificates_collection is not None:
            cert_count = certificates_collection.count_documents({})
            if cert_count == 0:
                demo_certificates = [
                    {
                        "student_name": "Raksha Varshney",
                        "father_name": "Chandra Shekhar Varshney",
                        "roll_number": "14BCOM10495",
                        "certificate_number": "KU/C-0151359",
                        "institution_id": "KOLHAN_UNIVERSITY",
                        "university": "Kolhan University",
                        "college": "Jamshedpur Women's College, Jamshedpur",
                        "degree": "Bachelor of Commerce, Accounts (Honours)",
                        "examination_year": "2017",
                        "passing_month": "April",
                        "class": "First Class",
                        "issue_date": "21 FEB 2022",
                        "location": "Chaibasa, Jharkhand",
                        "extracted_text": "KOLHAN UNIVERSITY CHAIBASA JHARKHAND Bachelor of Commerce This is to certify that Raksha Varshney daughter of Chandra Shekhar Varshney Roll no 14BCOM10495 of Jamshedpur Women's College Jamshedpur An Autonomous Constituent Unit of K.U Passed the Bachelor of Commerce Accounts Honours Examination 2017 held in the month of April 2017 and placed in First Class the day admitted to the degree KU/C-0151359",
                        "hash": get_hash("KOLHAN UNIVERSITY CHAIBASA JHARKHAND Bachelor of Commerce This is to certify that Raksha Varshney daughter of Chandra Shekhar Varshney Roll no 14BCOM10495 of Jamshedpur Women's College Jamshedpur An Autonomous Constituent Unit of K.U Passed the Bachelor of Commerce Accounts Honours Examination 2017 held in the month of April 2017 and placed in First Class the day admitted to the degree KU/C-0151359")
                    },
                    {
                        "student_name": "Priya Sharma",
                        "father_name": "Rajesh Sharma",
                        "roll_number": "15BCOM10523",
                        "certificate_number": "KU/C-0151360",
                        "institution_id": "KOLHAN_UNIVERSITY",
                        "university": "Kolhan University",
                        "college": "Jamshedpur Women's College, Jamshedpur",
                        "degree": "Bachelor of Commerce, Marketing (Honours)",
                        "examination_year": "2017",
                        "passing_month": "April",
                        "class": "First Class",
                        "issue_date": "22 FEB 2022",
                        "location": "Chaibasa, Jharkhand",
                        "extracted_text": "KOLHAN UNIVERSITY CHAIBASA JHARKHAND Bachelor of Commerce This is to certify that Priya Sharma daughter of Rajesh Sharma Roll no 15BCOM10523 of Jamshedpur Women's College Jamshedpur An Autonomous Constituent Unit of K.U Passed the Bachelor of Commerce Marketing Honours Examination 2017 held in the month of April 2017 and placed in First Class the day admitted to the degree KU/C-0151360",
                        "hash": get_hash("KOLHAN UNIVERSITY CHAIBASA JHARKHAND Bachelor of Commerce This is to certify that Priya Sharma daughter of Rajesh Sharma Roll no 15BCOM10523 of Jamshedpur Women's College Jamshedpur An Autonomous Constituent Unit of K.U Passed the Bachelor of Commerce Marketing Honours Examination 2017 held in the month of April 2017 and placed in First Class the day admitted to the degree KU/C-0151360")
                    },
                    {
                        "student_name": "Amit Kumar",
                        "father_name": "Suresh Kumar",
                        "roll_number": "16BCOM10567",
                        "certificate_number": "KU/C-0151361",
                        "institution_id": "KOLHAN_UNIVERSITY",
                        "university": "Kolhan University",
                        "college": "Kolhan University Main Campus, Chaibasa",
                        "degree": "Bachelor of Commerce, Finance (Honours)",
                        "examination_year": "2018",
                        "passing_month": "April",
                        "class": "Second Class",
                        "issue_date": "15 MAR 2022",
                        "location": "Chaibasa, Jharkhand",
                        "extracted_text": "KOLHAN UNIVERSITY CHAIBASA JHARKHAND Bachelor of Commerce This is to certify that Amit Kumar son of Suresh Kumar Roll no 16BCOM10567 of Kolhan University Main Campus Chaibasa Passed the Bachelor of Commerce Finance Honours Examination 2018 held in the month of April 2018 and placed in Second Class the day admitted to the degree KU/C-0151361",
                        "hash": get_hash("KOLHAN UNIVERSITY CHAIBASA JHARKHAND Bachelor of Commerce This is to certify that Amit Kumar son of Suresh Kumar Roll no 16BCOM10567 of Kolhan University Main Campus Chaibasa Passed the Bachelor of Commerce Finance Honours Examination 2018 held in the month of April 2018 and placed in Second Class the day admitted to the degree KU/C-0151361")
                    }
                ]
                certificates_collection.insert_many(demo_certificates)
                print("Demo certificates created based on Kolhan University format.")
            else:
                print(f"Database already contains {cert_count} certificates.")
    
    except Exception as e:
        print(f"Error initializing demo data: {e}")

if __name__ == '__main__':
    print("Starting Certificate Validator Backend...")
    initialize_demo_data()
    print("Backend ready! Starting server...")
    app.run(debug=True, host='127.0.0.1', port=5000)
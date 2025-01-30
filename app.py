from flask import Flask, request, session, flash, redirect, url_for, render_template, g, json, jsonify
import re
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import timedelta, datetime
from typing import List, Dict, Tuple, Optional
import sqlite3
import PyPDF2
import math
import string
import mysql.connector
import random
import os
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mysqldb import MySQL
import io
from werkzeug.utils import secure_filename
from functools import wraps


app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.permanent_session_lifetime = timedelta(minutes=60)
app.config['SESSION_COOKIE_SECURE'] = True  # For HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'smtc_tracker'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # make sure this exists

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Create User class
class User(UserMixin):
    def __init__(self, id, name, is_admin):
        self.id = str(id)  # Flask-Login needs string ID
        self.name = name
        self.is_admin = is_admin

    def get_id(self):
        return self.id

# User loader callback
@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, name, is_admin FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if user:
        return User(
            id=user[0],
            name=user[1],
            is_admin=user[2]
        )
    return None

mysql = MySQL(app)
bcrypt = Bcrypt(app)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "1000 per hour"]
)

DATABASE = '/data/users.db'
os.makedirs('/data', exist_ok=True)  # Create the directory if it doesn't exist

def init_db():
    db = get_db()

    try:
        db.execute('ALTER TABLE parsed_receipts ADD COLUMN imei_iccid_pairs TEXT')
        db.commit()
    except sqlite3.OperationalError:
        # Column might already exist
        pass

def update_db():
    db = get_db()
    cursor = db.cursor()
    
    # Check if column exists
    cursor.execute("PRAGMA table_info(parsed_receipts)")
    columns = cursor.fetchall()
    column_names = [column[1] for column in columns]
    
    # Add column if it doesn't exist
    if 'imei_iccid_pairs' not in column_names:
        try:
            cursor.execute('ALTER TABLE parsed_receipts ADD COLUMN imei_iccid_pairs TEXT')
            db.commit()
            print("Added imei_iccid_pairs column")
        except sqlite3.OperationalError as e:
            print(f"Error adding column: {e}")
    else:
        print("Column already exists")

    # Create the users table
    db.execute('''
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE,
            password TEXT,
            approved INTEGER DEFAULT 0,
            is_admin INTEGER DEFAULT 0,
            rejected INTEGER DEFAULT 0
        );
    ''')

    # Create the parsed_receipts_new table
    db.execute('''
        CREATE TABLE IF NOT EXISTS parsed_receipts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_name TEXT,
            customer TEXT,
            order_date TEXT,
            sales_person TEXT,
            rq_invoice TEXT,
            total_price REAL,
            accessory_prices TEXT,
            upgrades_count INTEGER,
            activations_count INTEGER,
            ppp_present BOOLEAN,
            activation_fee_sum REAL,
            user_id INTEGER,
            date_submitted TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            imei_iccid_pairs TEXT,  -- Store as JSON string
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    ''')

    # These are the new lines added after your existing db.execute statements:
    
    # Check if admin user exists
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    admin_exists = cursor.fetchone()

    # Create default admin if it doesn't exist
    if not admin_exists:
        admin_password = bcrypt.generate_password_hash('admin123').decode('utf-8')
        db.execute('''
            INSERT INTO users (name, email, phone, username, password, approved, is_admin)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', ('Admin User', 'admin@example.com', '1234567890', 'admin', admin_password, 1, 1))

    

    db.commit()

ALLOWED_EXTENSIONS = {'pdf'}
def allowed_file(filename):
    """Check if the uploaded file has an allowed extension"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/update_receipt/<string:rq_invoice>', methods=['POST'])
@login_required
def update_receipt_details(rq_invoice):
    if not request.is_json:
        return jsonify({'error': 'Content-Type must be application/json'}), 400

    try:
        db = get_db()
        cursor = db.cursor()
        
        # Verify user has permission to edit this receipt
        cursor.execute("""
            SELECT user_id, imei_iccid_pairs
            FROM parsed_receipts 
            WHERE rq_invoice = ?
        """, (rq_invoice,))
        
        receipt = cursor.fetchone()
        
        if not receipt:
            return jsonify({'error': 'Receipt not found'}), 404
        
        updates = request.get_json()

        # Prepare update query and values dynamically
        update_columns = []
        update_values = []

        # Mapping of frontend field names to database column names
        field_mapping = {
            'store': 'company_name',
            'customer': 'customer',
            'order_date': 'order_date',
            'sales_person': 'sales_person',
            'total_price': 'total_price',
            'accessories': 'accessory_prices',
            'activation_fee': 'activation_fee_sum',
            'upgrades': 'upgrades_count',
            'activations': 'activations_count',
            'ppp_present': 'ppp_present'
        }

        # Handle device info updates
        if 'device_info' in updates:
            try:
                # Validate device info format
                for device in updates['device_info']:
                    if not isinstance(device, dict):
                        return jsonify({'error': 'Invalid device info format'}), 400
                    if not all(key in device for key in ['imei', 'iccid']):
                        return jsonify({'error': 'Missing IMEI or ICCID'}), 400
                    if not re.match(r'^\d{15}$', str(device['imei'])):
                        return jsonify({'error': 'IMEI must be exactly 15 digits'}), 400
                    if not re.match(r'^\d{19,20}$', str(device['iccid'])):
                        return jsonify({'error': 'ICCID must be 19-20 digits'}), 400

                # Store device info as JSON
                device_info = json.dumps(updates['device_info'])
                update_columns.append('imei_iccid_pairs = ?')
                update_values.append(device_info)
                del updates['device_info']
            except (TypeError, ValueError) as e:
                return jsonify({'error': f'Invalid device info format: {str(e)}'}), 400

        # Process other updates
        for frontend_field, value in updates.items():
            # Map frontend field to database column
            if frontend_field in field_mapping:
                db_column = field_mapping[frontend_field]
                update_columns.append(f'{db_column} = ?')
                update_values.append(value)

        # Construct and execute update query
        if update_columns:
            update_query = f"""
                UPDATE parsed_receipts 
                SET {', '.join(update_columns)}
                WHERE rq_invoice = ?
            """
            update_values.append(rq_invoice)

            cursor.execute(update_query, tuple(update_values))
            db.commit()

        return jsonify({'message': 'Receipt updated successfully'})

    except Exception as e:
        db.rollback()
        print(f"Error updating receipt: {str(e)}")
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/update_device_info/<int:receipt_id>', methods=['POST'])
def update_device_info(receipt_id):
    try:
        data = request.json
        
        cursor = mysql.connection.cursor()
        
        # Update IMEI/ICCID pairs
        for item in data:
            if 'imei' in item and 'iccid' in item:
                query = """
                    UPDATE device_info 
                    SET imei = %s, iccid = %s 
                    WHERE receipt_id = %s AND id = %s
                """
                cursor.execute(query, (item['imei'], item['iccid'], receipt_id, item['id']))
        
        mysql.connection.commit()
        cursor.close()
        
        return jsonify({'status': 'success', 'message': 'Device information updated successfully'})

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    
@app.route('/non_admin_dashboard')
def non_admin_dashboard():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    # If the user is not an admin, show them the dashboard with the three boxes
    if 'admin' not in session:
        # Get the username from session
        username = session.get('username')
        
        # Create database cursor
        db = get_db()
        
        # Query to get the user's name using the username
        cursor = db.execute("SELECT name FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if user:
            # Pass the name to the template
            return render_template('non_admin_dashboard.html', current_user=user[0])
        else:
            # Fallback to username if name not found
            return render_template('non_admin_dashboard.html', current_user=username)
    
    return redirect(url_for('admin_home'))# Redirect admins to their home page

@app.route('/delete_receipt/<int:receipt_id>', methods=['POST'])
def delete_receipt(receipt_id):
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()
    
    # Delete the receipt from the database
    cursor.execute("DELETE FROM parsed_receipts WHERE id = ?", (receipt_id,))
    db.commit()
    
    return redirect(url_for('view_receipts'))

def round_up(value, decimals=2):
    factor = 10 ** decimals
    return math.ceil(value * factor) / factor

# Database connection function
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
    return g.db

# Close the database connection at the end of each request
@app.teardown_appcontext
def close_connection(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

@app.route('/admin/pending_accounts')
def pending_accounts():
    if 'admin' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    
    # Select pending accounts for admin review
    cursor.execute("SELECT id, name, email, phone FROM users WHERE approved = 0")
    pending_users = cursor.fetchall()
    
    return render_template('pending_accounts.html', pending_users=pending_users)

# Route for registering new users
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        
        # Generate a random password
        password = generate_random_password(10)
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        db = get_db()
        try:
            # Save user with empty username and approved set to 0
            db.execute(
                "INSERT INTO users (name, email, phone, password, approved) VALUES (?, ?, ?, ?, 0)",
                (name, email, phone, hashed_password)
            )
            db.commit()
        except sqlite3.IntegrityError:
            return "Email or phone number already exists", 400

        # Send password to the user (e.g., via email)
        return "Your account has been created. Your password is: {}".format(password), 200
    
    return render_template('register.html')

def generate_random_password(length, include_special_chars=False):
    characters = string.ascii_letters + string.digits
    if include_special_chars:
        characters += string.punctuation

    password = ''.join(random.choice(characters) for
 _ in range(length))
    
    return password

# Single login route with rate limiting
@app.route('/', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            SELECT id, name, email, phone, username, password, approved, is_admin 
            FROM users 
            WHERE username = ?
        """, (username,))
        user_data = cursor.fetchone()
        
        if user_data and bcrypt.check_password_hash(user_data[5], password):  # password is at index 5
            if user_data[6] == 1:  # approved status at index 6
                # Create User object
                user = User(
                    id=user_data[0],      # id
                    name=user_data[1],    # name
                    is_admin=user_data[7]  # is_admin status at index 7
                )
                
                # Log in the user
                login_user(user)
                
                # Set session variables
                session.permanent = True
                session['logged_in'] = True
                session['username'] = username
                session['user_id'] = int(user_data[0])
                
                if user_data[7] == 1:  # is_admin
                    session['admin'] = True
                    return redirect(url_for('admin_home'))
                
                return redirect(url_for('non_admin_dashboard'))
            else:
                flash("Your account is pending approval. Please try again later.", "error")
                return redirect(url_for('login'))
        else:
            flash("Invalid username or password", "error")
            return redirect(url_for('login'))
        
    return render_template('login.html')

# Home route
@app.route('/home')
def home():
    if 'logged_in' in session:
        # Check if the user is an admin
        if 'admin' in session:
            return redirect(url_for('employee_list'))  # Redirect admins to the employee list
        return redirect(url_for('upload_pdf'))  # Redirect regular users to the PDF upload page
    else:
        return redirect(url_for('login'))

@app.route('/admin/home')
def admin_home():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT name FROM users WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    if 'admin' not in session:
        return redirect(url_for('login'))
    current_user = user[0] if user else 'User'
    
    return render_template('admin_home.html', current_user=current_user)

# Admin page to list employees and approve/reject accounts
@app.route('/admin/employees')
def employee_list():
    if 'admin' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT id, name, email, phone, username, approved, is_admin, rejected FROM users")
    employees = cursor.fetchall()
    cursor.execute("SELECT name FROM users WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    current_user = user[0] if user else 'User'
    return render_template('employee_list.html', employees=employees, current_user=current_user)

@app.route('/admin/commission')
def view_commission():
    if 'admin' not in session:
        return redirect(url_for('login'))
    
    return "<h1>Commission Information Page</h1><p>This page will show commissions of all employees.</p>"

@app.route('/admin/assign_username/<int:user_id>', methods=['POST'])
def assign_username(user_id):
    if 'admin' not in session:
        return redirect(url_for('login'))

    username = request.form['username']

    db = get_db()
    cursor = db.cursor()

    cursor.execute("UPDATE users SET username = ? WHERE id = ?", (username, user_id))
    db.commit()

    return redirect(url_for('employee_list'))

@app.route('/admin/approve_user/<int:user_id>', methods=['POST'])
def approve_user_account(user_id):
    if 'admin' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    
    # Set approved status to 1
    cursor.execute("UPDATE users SET approved = 1 WHERE id = ?", (user_id,))
    db.commit()
    
    return redirect(url_for('employee_list'))

@app.route('/admin/approve/<int:user_id>', methods=['POST'])
def approve_account(user_id):
    if 'admin' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # Update the user's approved status to 1
    cursor.execute("UPDATE users SET approved = 1, rejected = 0 WHERE id = ?", (user_id,))
    db.commit()

    return redirect(url_for('employee_list'))

@app.route('/admin/reject/<int:user_id>', methods=['POST'])
def reject_account(user_id):
    if 'admin' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # Set the rejected flag to 1
    cursor.execute("UPDATE users SET rejected = 1, approved = 0 WHERE id = ?", (user_id,))
    db.commit()

    return redirect(url_for('employee_list'))

@app.route('/admin/delete/<int:user_id>', methods=['POST'])
def delete_account(user_id):
    if 'admin' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    
    # Delete the user by ID
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    
    return redirect(url_for('employee_list'))

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('admin', None)
    return redirect(url_for('login'))

def extract_imei_iccid_pairs(text):
    """
    Extract IMEI and ICCID pairs in order of appearance in the document.
    """
    pairs = []
    lines = text.split('\n')
    current_imei = None
    
    for line in lines:
        if 'IMEI:' in line:
            imei_match = re.search(r'IMEI:(\d{15})', line)
            if imei_match:
                current_imei = imei_match.group(1)
        elif 'ICCID:' in line and current_imei:
            iccid_match = re.search(r'ICCID:(\d{20})', line)
            if iccid_match:
                iccid = iccid_match.group(1)
                pairs.append({
                    'imei': current_imei,
                    'iccid': iccid
                })
                current_imei = None  # Reset current_imei after creating a pair
    
    return pairs

def pair_imei_iccid(imeis: List[str], iccids: List[str]) -> List[Dict[str, str]]:
    """Create pairs of IMEI and ICCID numbers preserving order."""
    pairs = []
    
    # Create pairs while maintaining order
    for i in range(min(len(imeis), len(iccids))):
        pairs.append({
            'imei': imeis[i],
            'iccid': iccids[i]
        })
    
    return pairs

def extract_info_from_pdf(pdf_file) -> Tuple:
    """Extract all information from PDF file."""
    reader = PyPDF2.PdfReader(pdf_file)
    pdf_text = ""
    
    for page in reader.pages:
        pdf_text += page.extract_text()

    # Regular expression patterns
    company_pattern = r"Sale\nR\d+\n(\d{3}:\s[A-Za-z\s]+)"
    customer_pattern = r"Customer\s*(.*?)(?:\n|\s*\()"
    order_date_pattern = r"Order Date\s*(\d{1,2}-\w{3}-\d{4}\s*\d{1,2}:\d{2}:\d{2}\s*\w*)"
    sales_person_pattern = r"Tendered By:\s*(.*?)(?:\n|$)"
    rq_invoice_pattern = r"Sale\n(R\d+)\n"
    
    # Get IMEI/ICCID pairs
    imei_iccid_pairs = extract_imei_iccid_pairs(pdf_text)
    
    # Other patterns
    upgrades_pattern = r"\bUpgrade Fee\b"
    activations_pattern = r"\bActivation Fee\b"
    ppp_pattern = r"\bLease\b"
    activation_fee_pattern = r"Fee\s*\d\s*@\$\s*([\d.]+)"

    # Extract data
    company_name = re.search(company_pattern, pdf_text, re.DOTALL)
    customer = re.search(customer_pattern, pdf_text, re.DOTALL)
    order_date = re.search(order_date_pattern, pdf_text, re.DOTALL)
    sales_person = re.search(sales_person_pattern, pdf_text, re.DOTALL)
    rq_invoice = re.search(rq_invoice_pattern, pdf_text, re.DOTALL)
    
    # Count occurrences
    upgrades_count = len(re.findall(upgrades_pattern, pdf_text, re.IGNORECASE))
    activations_count = len(re.findall(activations_pattern, pdf_text, re.IGNORECASE))
    ppp_present = bool(re.search(ppp_pattern, pdf_text, re.IGNORECASE))
    
    # Calculate activation fees
    activation_fees = re.findall(activation_fee_pattern, pdf_text)
    activation_fee_sum = round(sum(float(fee) for fee in activation_fees), 2)

    # Calculate accessories (moved to separate function)
    total_price, accessory_prices = calculate_accessories(pdf_text)

    return (
        company_name.group(1).strip() if company_name else "N/A",
        customer.group(1).strip() if customer else "N/A",
        order_date.group(1).strip() if order_date else "N/A",
        sales_person.group(1).strip() if sales_person else "N/A",
        rq_invoice.group(1).strip() if rq_invoice else "N/A",
        total_price,
        accessory_prices,
        upgrades_count,
        activations_count,
        ppp_present,
        imei_iccid_pairs,
        activation_fee_sum
    )

def calculate_accessories(pdf_text: str) -> Tuple[float, List[float]]:
    """Calculate accessory prices from PDF text."""
    accessory_pattern = r'([A-Z0-9]+)\n(.*?)\n(?:.*?@\$(\d+\.\d+)).*?Item Total\s+\$(\d+\.\d+)'
    non_accessory_identifiers = [
        'DEFBYOD', 'UNLCOR', 'UNLMORE', 'ACTIVATION',
        'IMEI:', 'ICCID:', 'SIM', 'STHN', 'SSGN',
        '55UNL', '60UNL'
    ]
    
    accessory_prices = []
    for match in re.finditer(accessory_pattern, pdf_text, re.DOTALL):
        sku = match.group(1)
        description = match.group(2).strip()
        final_price = float(match.group(4))
        
        if not any(identifier in sku or identifier in description 
                  for identifier in non_accessory_identifiers):
            accessory_prices.append(round(final_price, 2))
    
    total_price = round(sum(accessory_prices), 2)
    return total_price, accessory_prices

# PDF upload page
@app.route('/upload', methods=['GET', 'POST'])
def upload_pdf():
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    # Handle GET request - return the upload form template
    if request.method == 'GET':
        # Get logged in user's name for the template
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT name FROM users WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        current_user = user[0] if user else 'User'
        return render_template('upload.html', current_user=current_user)
    
    # Handle POST request - file upload
    try:
        print("Request files:", request.files)
        
        if 'pdf[]' not in request.files and 'pdf' not in request.files:
            print("No files in request")
            return jsonify({'error': 'No files were uploaded'}), 400

        # Handle both multiple and single file uploads
        if 'pdf[]' in request.files:
            files = request.files.getlist('pdf[]')
        else:
            files = [request.files['pdf']]

        if not files or not any(file.filename for file in files):
            print("No files selected")
            return jsonify({'error': 'No files selected'}), 400

        uploaded_files = []
        errors = []
        parsed_data_list = []
        
        print(f"Processing {len(files)} files")
        
        for file in files:
            if file and file.filename and allowed_file(file.filename):
                try:
                    filename = secure_filename(file.filename)
                    print(f"Processing file: {filename}")
                    
                    # Read file content
                    file_content = file.read()
                    file_stream = io.BytesIO(file_content)
                    
                    # Process PDF
                    reader = PyPDF2.PdfReader(file_stream)
                    pdf_text = "".join(page.extract_text() for page in reader.pages)
                    
                    # Reset file stream for extract_info_from_pdf
                    file_stream.seek(0)
                    
                    # Extract information
                    (company_name, customer, order_date, sales_person, rq_invoice, 
                     total_price, accessories_prices, upgrades_count, activations_count, 
                     ppp_present, pairs, activation_fee_sum) = extract_info_from_pdf(file_stream)
                    
                    parsed_data = {
                        'filename': filename,
                        'company_name': company_name,
                        'customer': customer,
                        'order_date': order_date,
                        'sales_person': sales_person,
                        'rq_invoice': rq_invoice,
                        'total_price': total_price,
                        'accessories_prices': accessories_prices,
                        'upgrades_count': upgrades_count,
                        'activations_count': activations_count,
                        'ppp_present': ppp_present,
                        'activation_fee_sum': activation_fee_sum,
                        'imei_iccid_pairs': pairs,
                        'pdf_text': pdf_text
                    }
                    
                    parsed_data_list.append(parsed_data)
                    uploaded_files.append(filename)
                    print(f"Successfully processed {filename}")
                    
                except Exception as e:
                    print(f"Error processing {file.filename}: {str(e)}")
                    errors.append(f"Error processing {file.filename}: {str(e)}")
            else:
                error_msg = f"Invalid file: {file.filename if file.filename else 'No file selected'}"
                print(error_msg)
                errors.append(error_msg)

        if not parsed_data_list:
            if errors:
                return jsonify({'error': ' | '.join(errors)}), 400
            return jsonify({'error': 'No valid files were processed'}), 400

        # Store the list of parsed data in session
        session['parsed_data_list'] = parsed_data_list
        session['current_pdf_index'] = 0

        response_data = {
            'status': 'success',
            'message': f'Successfully processed {len(uploaded_files)} files',
            'uploaded': uploaded_files,
            'redirect': url_for('confirm_receipt')
        }
        print("Sending response:", response_data)
        return jsonify(response_data)
        
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return jsonify({'error': str(e)}), 500
    
@app.route('/confirm', methods=['GET', 'POST'])
def confirm_receipt():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    if 'parsed_data_list' not in session:
        return redirect(url_for('upload_pdf'))
    
    parsed_data_list = session.get('parsed_data_list', [])
    current_index = session.get('current_pdf_index', 0)
    
    if current_index >= len(parsed_data_list):
        # All PDFs have been processed
        session.pop('parsed_data_list', None)
        session.pop('current_pdf_index', None)
        return redirect(url_for('view_receipts'))
    
    # Get current PDF data
    current_pdf = parsed_data_list[current_index]
    
    # Get logged in user's name
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT name FROM users WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    logged_in_user = user[0] if user else None
    
    if request.method == 'POST':
        if not session.get('user_id'):
            return redirect(url_for('login'))
        
        # Process form data
        form_data = {
            'company_name': request.form.get('company_name', 'N/A'),
            'customer': request.form.get('customer', 'N/A'),
            'order_date': request.form.get('order_date', 'N/A'),
            'sales_person': request.form.get('sales_person', 'N/A'),
            'rq_invoice': request.form.get('rq_invoice', 'N/A'),
            'total_price': float(request.form.get('total_price', 0)),
            'accessories_prices': request.form.get('accessories_prices', ''),
            'upgrades_count': int(request.form.get('upgrades_count', 0)),
            'activations_count': int(request.form.get('activations_count', 0)),
            'ppp_present': 'ppp_present' in request.form,
            'activation_fee_sum': float(request.form.get('activation_fee_sum', 0))
        }

        imei_iccid_pairs = current_pdf.get('imei_iccid_pairs', [])
        
        # Convert pairs to JSON string for storage
        imei_iccid_json = json.dumps(imei_iccid_pairs)
        
        
        # Save to database
        cursor.execute('''
            INSERT INTO parsed_receipts (
                company_name, customer, order_date, sales_person, rq_invoice, 
                total_price, accessory_prices, upgrades_count, activations_count, 
                ppp_present, activation_fee_sum, user_id, imei_iccid_pairs
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            form_data['company_name'], form_data['customer'], form_data['order_date'],
            form_data['sales_person'], form_data['rq_invoice'], form_data['total_price'],
            form_data['accessories_prices'], form_data['upgrades_count'],
            form_data['activations_count'], form_data['ppp_present'],
            form_data['activation_fee_sum'], session['user_id'], imei_iccid_json
        ))
        
        db.commit()
        
        # Move to next PDF
        session['current_pdf_index'] = current_index + 1
        
        if current_index + 1 >= len(parsed_data_list):
            # All PDFs processed
            session.pop('parsed_data_list', None)
            session.pop('current_pdf_index', None)
            return redirect(url_for('view_receipts'))
        
        return redirect(url_for('confirm_receipt'))
    
    # For GET request, display the current PDF's data
    current_pdf['logged_in_user'] = logged_in_user
    total_pdfs = len(parsed_data_list)
    current_number = current_index + 1
    
    return render_template('confirm_receipt.html', 
                         current_user=logged_in_user,
                         total_pdfs=total_pdfs,
                         current_pdf_number=current_number,
                         **current_pdf)

@app.route('/view_receipts')
def view_receipts():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()

    # Get the current user's name
    cursor.execute("SELECT name FROM users WHERE id = ?", (session['user_id'],))
    user_data = cursor.fetchone()
    current_user = user_data[0] if user_data else 'User'

    # Fetch user details to check if the logged-in user is an admin
    cursor.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    
    if user and user[7] == 1:  # Admin user
        cursor.execute("""
            SELECT 
             r.*, u.name as uploader_name
            FROM parsed_receipts r
            LEFT JOIN users u ON r.user_id = u.id
            ORDER BY r.date_submitted DESC
        """)
    else:
        cursor.execute("""
            SELECT 
             r.*, u.name as uploader_name
            FROM parsed_receipts r
            LEFT JOIN users u ON r.user_id = u.id
            WHERE r.user_id = ?
        """, (session['user_id'],))
    
    receipts = cursor.fetchall()
    return render_template('view_receipts.html', receipts=receipts, current_user=current_user)

@app.route('/receipt_details/<string:rq_invoice>')
def receipt_details(rq_invoice):
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # Fetch user details to check if admin
    cursor.execute("SELECT id, name, is_admin FROM users WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    is_admin = user and user[2] == 1
    current_user = user[1] if user else 'User'

    # Fetch receipt details
    if is_admin:
        cursor.execute("""
            SELECT 
                r.id,
                r.company_name,
                r.customer,
                r.order_date,
                r.sales_person,
                r.rq_invoice,
                r.total_price,
                r.accessory_prices,
                r.upgrades_count,
                r.activations_count,
                r.ppp_present,
                r.activation_fee_sum,
                r.imei_iccid_pairs,
                u.name as uploader_name
            FROM parsed_receipts r
            LEFT JOIN users u ON r.user_id = u.id
            WHERE r.rq_invoice = ?
        """, (rq_invoice,))
    else:
        cursor.execute("""
            SELECT 
                r.id,
                r.company_name,
                r.customer,
                r.order_date,
                r.sales_person,
                r.rq_invoice,
                r.total_price,
                r.accessory_prices,
                r.upgrades_count,
                r.activations_count,
                r.ppp_present,
                r.activation_fee_sum,
                r.imei_iccid_pairs,
                u.name as uploader_name
            FROM parsed_receipts r
            LEFT JOIN users u ON r.user_id = u.id
            WHERE r.rq_invoice = ? AND r.user_id = ?
        """, (rq_invoice, session['user_id']))

    receipt = cursor.fetchone()
    if not receipt:
        return "Receipt not found", 404
    
    imei_iccid_pairs = []
    if receipt and receipt[12]:  # Assuming imei_iccid_pairs is the last column
        try:
            imei_iccid_pairs = json.loads(receipt[12])
        except (json.JSONDecodeError, TypeError):
            pass

    return render_template('receipt_details.html', receipt=receipt, imei_iccid_pairs=imei_iccid_pairs, current_user=current_user)

@app.route('/commission')
def commission():
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    
    # Check if user is admin
    cursor.execute("SELECT is_admin FROM users WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    is_admin = user and user[0] == 1
    current_user = user[0] if user else 'User'

    if is_admin:
        cursor.execute('''
            SELECT 
                users.username, 
                users.name,
                SUM(COALESCE(parsed_receipts.activations_count, 0)) as total_activations,
                SUM(COALESCE(parsed_receipts.upgrades_count, 0)) as total_upgrades,
                SUM(COALESCE(parsed_receipts.activations_count, 0) + COALESCE(parsed_receipts.upgrades_count, 0)) as total_devices,
                COALESCE(SUM(parsed_receipts.total_price), 0) as total_accessories,
                CASE 
                    WHEN COALESCE(SUM(parsed_receipts.total_price), 0) >= 1750 THEN 4
                    WHEN COALESCE(SUM(parsed_receipts.total_price), 0) >= 1000 THEN 3
                    WHEN COALESCE(SUM(parsed_receipts.total_price), 0) >= 750 THEN 2
                    WHEN COALESCE(SUM(parsed_receipts.total_price), 0) >= 500 THEN 1
                    ELSE 1
                END as current_tier
            FROM 
                users
            LEFT JOIN 
                parsed_receipts ON users.id = parsed_receipts.user_id
            WHERE
                users.is_admin = 0
            GROUP BY 
                users.username, users.name
        ''')
        commission_data = cursor.fetchall()
        return render_template('commission.html', 
                             commission_data=commission_data, 
                             is_admin=is_admin,
                             current_user=current_user)
    else:
        cursor.execute('''
            SELECT 
                users.username, 
                users.name,
                SUM(COALESCE(parsed_receipts.activations_count, 0)) as total_activations,
                SUM(COALESCE(parsed_receipts.upgrades_count, 0)) as total_upgrades,
                SUM(COALESCE(parsed_receipts.activations_count, 0) + COALESCE(parsed_receipts.upgrades_count, 0)) as total_devices,
                COALESCE(SUM(parsed_receipts.total_price), 0) as total_accessories,
                CASE 
                    WHEN COALESCE(SUM(parsed_receipts.total_price), 0) >= 1750 THEN 4
                    WHEN COALESCE(SUM(parsed_receipts.total_price), 0) >= 1000 THEN 3
                    WHEN COALESCE(SUM(parsed_receipts.total_price), 0) >= 750 THEN 2
                    WHEN COALESCE(SUM(parsed_receipts.total_price), 0) >= 500 THEN 1
                    ELSE 1
                END as current_tier
            FROM 
                users
            LEFT JOIN 
                parsed_receipts ON users.id = parsed_receipts.user_id
            WHERE 
                users.id = ?
            GROUP BY 
                users.username, users.name
        ''', (session['user_id'],))

        commission_data = cursor.fetchall()
        
        # Calculate accessories total and progress
        accessories_total = commission_data[0][5] if commission_data else 0
        progress = min((float(accessories_total) / 1750 * 100), 100)
        
        # Get tier from the query result
        current_tier = commission_data[0][6] if commission_data else 1

        return render_template('commission.html', 
                             commission_data=commission_data, 
                             is_admin=is_admin,
                             accessories_total=accessories_total,
                             current_tier=current_tier,
                             progress=progress,
                             current_user=current_user)

if __name__ == '__main__':
    with app.app_context():
        init_db()  # Initialize the database tables
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port,debug=True)
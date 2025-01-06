from flask import Flask, request, session, redirect, url_for, render_template, g
import re
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import timedelta
from typing import List, Dict, Tuple, Optional
import sqlite3
import PyPDF2
import math
import string
import random
import os
import json
import io

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.permanent_session_lifetime = timedelta(minutes=60)
app.config['SESSION_COOKIE_SECURE'] = True  # For HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

bcrypt = Bcrypt(app)
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

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

@app.route('/non_admin_dashboard')
def non_admin_dashboard():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    # If the user is not an admin, show them the dashboard with the three boxes
    if 'admin' not in session:
        return render_template('non_admin_dashboard.html')
    
    return redirect(url_for('admin_home'))  # Redirect admins to their home page

@app.route('/edit_receipt/<int:receipt_id>', methods=['GET', 'POST'])
def edit_receipt(receipt_id):
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()

    # Handle form submission for editing
    if request.method == 'POST':
        company_name = request.form['company_name']
        customer = request.form['customer']
        order_date = request.form['order_date']
        sales_person = request.form['sales_person']
        rq_invoice = request.form['rq_invoice']
        total_price = float(request.form['total_price'])
        # Add this line to handle accessory_prices
        accessory_prices = request.form.get('accessory_prices', '')  # Default to empty string if missing
        upgrades_count = int(request.form['upgrades_count'])
        activations_count = int(request.form['activations_count'])
        ppp_present = bool(request.form.get('ppp_present'))
        activation_fee_sum = float(request.form['activation_fee_sum'])

        # Update the receipt in the database
        cursor.execute('''
            UPDATE parsed_receipts
            SET company_name = ?, customer = ?, order_date = ?, sales_person = ?, rq_invoice = ?,
                total_price = ?, accessory_prices = ?, upgrades_count = ?, activations_count = ?,
                ppp_present = ?, activation_fee_sum = ?
            WHERE id = ?
        ''', (company_name, customer, order_date, sales_person, rq_invoice, total_price, accessory_prices,
              upgrades_count, activations_count, ppp_present, activation_fee_sum, receipt_id))
        
        db.commit()
        return redirect(url_for('view_receipts'))

    # Fetch the receipt data for editing
    cursor.execute("SELECT * FROM parsed_receipts WHERE id = ?", (receipt_id,))
    receipt = cursor.fetchone()
    
    return render_template('edit_receipt.html', receipt=receipt)

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
        
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if user and bcrypt.check_password_hash(user[5], password):  # Assuming password is in the 3rd column
            if user[6] == 1:  # Assuming approved status is in the 4th column
                session.permanent = True
                session['logged_in'] = True
                session['username'] = username
                session['user_id'] = user[0]
                
                # Check if the user is an admin
                if user[7] == 1:  # Assuming is_admin status is in the 5th column
                    session['admin'] = True
                    return redirect(url_for('admin_home'))  # Redirect to the Admin Home Page

                return redirect(url_for('non_admin_dashboard'))  # Redirect regular users to the PDF upload page
            else:
                return "Your account is pending approval. Please try again later."
        else:
            return "Invalid credentials", 401

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
    if 'admin' not in session:
        return redirect(url_for('login'))
    
    return render_template('admin_home.html')

# Admin page to list employees and approve/reject accounts
@app.route('/admin/employees')
def employee_list():
    if 'admin' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT id, name, email, phone, username, approved, is_admin, rejected FROM users")
    employees = cursor.fetchall()
    return render_template('employee_list.html', employees=employees)

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

@app.route('/admin/view_all_users')
def view_all_users():
    if 'admin' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    
    # Query to get all user details
    cursor.execute("SELECT id, name, email, phone, username, approved, is_admin FROM users")
    users = cursor.fetchall()
    
    return render_template('admin_users.html', users=users)

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

    if request.method == 'POST' and 'pdf' in request.files:
        uploaded_file = request.files['pdf']
        if uploaded_file and uploaded_file.filename.endswith('.pdf'):
            # Store PDF text content
            reader = PyPDF2.PdfReader(uploaded_file)
            pdf_text = "".join(page.extract_text() for page in reader.pages)
            session['pdf_text'] = pdf_text
            
            # Parse PDF data
            (company_name, customer, order_date, sales_person, rq_invoice, 
             total_price, accessories_prices, upgrades_count, activations_count, 
             ppp_present, pairs, activation_fee_sum) = extract_info_from_pdf(uploaded_file)
            
            session['parsed_data'] = {
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
                'imei_iccid_pairs': pairs
            }
            
            return redirect(url_for('confirm_receipt'))
    
    elif request.method == 'POST':  # Handle the form submission for data entry
        company_name = request.form['company_name']
        customer = request.form['customer']
        order_date = request.form['order_date']
        sales_person = request.form['sales_person']
        rq_invoice = request.form['rq_invoice']
        total_price = request.form['total_price']
        accessory_prices = request.form['accessory_prices']
        upgrades_count = request.form['upgrades_count']
        activations_count = request.form['activations_count']
        ppp_present = request.form['ppp_present']
        activation_fee_sum = request.form['activation_fee_sum']

        # Ensure parsed data exists, if user comes from PDF parsing page
        if 'parsed_data' in session:
            parsed_data = session['parsed_data']
            company_name = parsed_data['company_name']
            customer = parsed_data['customer']
            order_date = parsed_data['order_date']
            sales_person = parsed_data['sales_person']
            rq_invoice = parsed_data['rq_invoice']
            total_price = parsed_data['total_price']
            accessory_prices = parsed_data['accessories_prices']
            upgrades_count = parsed_data['upgrades_count']
            activations_count = parsed_data['activations_count']
            ppp_present = parsed_data['ppp_present']
            activation_fee_sum = parsed_data['activation_fee_sum']
        
        # Get the username from the session (assuming the username is stored in session)
        username = session.get('username')  # Retrieve the username from session

        # Check if username is available in the session
        if not username:
            return redirect(url_for('login'))  # If no username in session, redirect to login

        # Save the parsed data into the database with the current user's username
        db = get_db()
        cursor = db.cursor()

        cursor.execute(''' 
            INSERT INTO parsed_receipts (company_name, customer, order_date, sales_person, 
                                         rq_invoice, total_price, accessory_prices, upgrades_count,
                                         activations_count, ppp_present, activation_fee_sum, username)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (company_name, customer, order_date, sales_person, rq_invoice, total_price, 
              accessory_prices, upgrades_count, activations_count, ppp_present, activation_fee_sum, username))

        db.commit()

        # After storing, clear the session's parsed data (optional cleanup step)
        session.pop('parsed_data', None)

        return redirect(url_for('view_receipts'))

    # If it's a GET request, render the upload page
    return render_template('upload.html')

@app.route('/confirm', methods=['GET', 'POST'])
def confirm_receipt():
    if 'logged_in' not in session:
        return redirect(url_for('login') + '?session_expired=true')
    
    if 'parsed_data' not in session or 'pdf_text' not in session:
        return redirect(url_for('upload_pdf'))
    
    # Get logged in user's name
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT name FROM users WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    logged_in_user = user[0] if user else None
    
    if request.method == 'POST':
        user_id = session.get('user_id')
        if not user_id:
            return redirect(url_for('login'))
        
        # Get form data
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
        
        # Get IMEI/ICCID pairs from session and convert to JSON string
        imei_iccid_pairs = session.get('parsed_data', {}).get('imei_iccid_pairs', [])
        imei_iccid_json = json.dumps(imei_iccid_pairs)
        
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
            form_data['activation_fee_sum'], user_id, imei_iccid_json
        ))
        
        db.commit()
        session.pop('parsed_data', None)
        return redirect(url_for('view_receipts'))
    
    if request.method == 'POST':
        user_id = session.get('user_id')
        if not user_id:
            return redirect(url_for('login'))
        
        # Get form data
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
        
        # Insert into database
        cursor.execute('''
            INSERT INTO parsed_receipts (
                company_name, customer, order_date, sales_person, rq_invoice, 
                total_price, accessory_prices, upgrades_count, activations_count, 
                ppp_present, activation_fee_sum, user_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            form_data['company_name'], form_data['customer'], form_data['order_date'],
            form_data['sales_person'], form_data['rq_invoice'], form_data['total_price'],
            form_data['accessories_prices'], form_data['upgrades_count'],
            form_data['activations_count'], form_data['ppp_present'],
            form_data['activation_fee_sum'], user_id
        ))
        
        db.commit()
        session.pop('parsed_data', None)
        return redirect(url_for('view_receipts'))
    
    # GET request
    parsed_data = session['parsed_data']
    pdf_text = session['pdf_text']
    
    parsed_data['imei_iccid_pairs'] = extract_imei_iccid_pairs(pdf_text)
    parsed_data['logged_in_user'] = logged_in_user

    return render_template('confirm_receipt.html', **parsed_data)

@app.route('/view_receipts')
def view_receipts():
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

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
    return render_template('view_receipts.html', receipts=receipts)

@app.route('/receipt_details/<string:rq_invoice>')
def receipt_details(rq_invoice):
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # Fetch user details to check if admin
    cursor.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    is_admin = user and user[7] == 1

    # Fetch receipt details
    if is_admin:
        cursor.execute("""
            SELECT 
            r.*, u.name as uploader_name
            FROM parsed_receipts r
            LEFT JOIN users u ON r.user_id = u.id
            WHERE r.rq_invoice = ?
        """, (rq_invoice,))
    else:
        cursor.execute("""
            SELECT 
            r.*, u.name as uploader_name
            FROM parsed_receipts r
            LEFT JOIN users u ON r.user_id = u.id
            WHERE r.rq_invoice = ? AND r.user_id = ?
        """, (rq_invoice, session['user_id']))

    receipt = cursor.fetchone()
    if not receipt:
        return "Receipt not found", 404
    
    imei_iccid_pairs = []
    if receipt and receipt[-1]:  # Assuming imei_iccid_pairs is the last column
        try:
            imei_iccid_pairs = json.loads(receipt[-1])
        except (json.JSONDecodeError, TypeError):
            pass

    return render_template('receipt_details.html', receipt=receipt, imei_iccid_pairs=imei_iccid_pairs)

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
                             is_admin=is_admin)
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
                             progress=progress)

if __name__ == '__main__':
    with app.app_context():
        init_db()  # Initialize the database tables
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port,debug=True)
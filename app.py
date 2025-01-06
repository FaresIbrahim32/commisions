from flask import Flask, request, session, redirect, url_for, render_template, g
import re
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import timedelta
import sqlite3
import PyPDF2
import math
import string
import random
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.permanent_session_lifetime = timedelta(minutes=15)

bcrypt = Bcrypt(app)
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

DATABASE = '/data/users.db'
os.makedirs('/data', exist_ok=True)  # Create the directory if it doesn't exist

def init_db():
    db = get_db()
    
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

def extract_imei_from_pdf(pdf_file):
    reader = PyPDF2.PdfReader(pdf_file)
    pdf_text = ""
    
    for page in reader.pages:
        pdf_text += page.extract_text()
    
    # Clean up text if needed
    pdf_text = re.sub(r'1@\$[0-9.]+\s*\$[0-9.]+', '', pdf_text)
    
    # Extract IMEI numbers
    imei_pattern = r'IMEI:(\d{15})'
    imei_matches = re.findall(imei_pattern, pdf_text)
    
    return imei_matches

def extract_iccid_from_pdf(pdf_file):
    reader = PyPDF2.PdfReader(pdf_file)
    pdf_text = ""
    
    for page in reader.pages:
        pdf_text += page.extract_text()
    
    # Clean up text if needed
    pdf_text = re.sub(r'1@\$[0-9.]+\s*\$[0-9.]+', '', pdf_text)
    
    # Extract ICCID numbers
    iccid_pattern = r'ICCID:(\d{20})'
    iccid_matches = re.findall(iccid_pattern, pdf_text)
    
    return iccid_matches

def pair_imei_iccid(imeis, iccids):
    # Create pairs, ensuring we don't exceed the shorter list
    imei_iccid_pairs = []
    for i in range(min(len(imeis), len(iccids))):
        imei_iccid_pairs.append({
            'imei': imeis[i],
            'iccid': iccids[i]
        })
    
    return imei_iccid_pairs

# Function to extract info from PDF
def extract_info_from_pdf(pdf_file):
    reader = PyPDF2.PdfReader(pdf_file)
    pdf_text = ""
    
    for page in reader.pages:
        pdf_text += page.extract_text()

    # Regular expression patterns
    imei_pattern = r'IMEI:\d+'
    company_pattern = r"Sale\nR\d+\n(\d{3}:\s[A-Za-z\s]+)"
    customer_pattern = r"Customer\s*(.*?)(?:\n|\s*\()"
    order_date_pattern = r"Order Date\s*(\d{1,2}-\w{3}-\d{4}\s*\d{1,2}:\d{2}:\d{2}\s*\w*)"
    sales_person_pattern = r"Tendered By:\s*(.*?)(?:\n|$)"
    rq_invoice_pattern = r"Sale\n(R\d+)\n"

    # Accessory pattern with explicit SKU formats
    accessory_pattern = r'([A-Z0-9]+)\n(.*?)\n(?:.*?@\$(\d+\.\d+)).*?Item Total\s+\$(\d+\.\d+)'
    
    # Pattern to match IMEI numbers
    imeis = extract_imei_from_pdf(pdf_file)
    iccids = extract_iccid_from_pdf(pdf_file)
    
    imei_iccid_pairs = pair_imei_iccid(imeis, iccids)
    
    # Define what SKUs or descriptions are NOT accessories
    non_accessory_identifiers = [
        'DEFBYOD',      # Device
        'UNLCOR',       # Plan
        'UNLMORE',      # Plan
        'ACTIVATION',
        '%IMEI%',   # Fee
        'ICCID:',       # SIM
        'SIM',          # SIM card
        'STHN',         # SIM
        'SSGN',         # SIM
        '55UNL',        # Plan
        '60UNL',        # Plan
    ]
    
    upgrades_pattern = r"\bUpgrade Fee\b"
    activations_pattern = r"\bActivation Fee\b"
    ppp_pattern = r"\bLease\b"
    activation_fee_pattern = r"Fee\s*\d\s*@\$\s*([\d.]+)"

    # Extract accessories using new pattern
    accessory_matches = re.finditer(accessory_pattern, pdf_text, re.DOTALL)
    accessory_prices = []
    
    for match in accessory_matches:
        sku = match.group(1)
        description = match.group(2).strip()
        final_price = float(match.group(4))
        
        # Skip if it contains an IMEI number
        if re.search(imei_pattern, description):
            continue
        
        # Skip if it matches any non-accessory identifier
        if any(identifier in sku or identifier in description 
               for identifier in non_accessory_identifiers):
            continue
            
        # Only add to accessories if it's a genuine accessory
        accessory_prices.append(round_up(final_price, 2))

    total_price = round_up(sum(accessory_prices), 2)

    # Extract other data
    company_name = re.search(company_pattern, pdf_text, re.DOTALL)
    customer = re.search(customer_pattern, pdf_text, re.DOTALL)
    order_date = re.search(order_date_pattern, pdf_text, re.DOTALL)
    sales_person = re.search(sales_person_pattern, pdf_text, re.DOTALL)
    rq_invoice = re.search(rq_invoice_pattern, pdf_text, re.DOTALL)

    upgrades_count = len(re.findall(upgrades_pattern, pdf_text, re.IGNORECASE))
    activations_count = len(re.findall(activations_pattern, pdf_text, re.IGNORECASE))
    ppp_present = bool(re.search(ppp_pattern, pdf_text, re.IGNORECASE))
    activation_fees = re.findall(activation_fee_pattern, pdf_text)
    activation_fee_sum = round_up(sum(float(fee) for fee in activation_fees), 2)

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
        activation_fee_sum)

# PDF upload page
@app.route('/upload', methods=['GET', 'POST'])
def upload_pdf():
    if request.method == 'POST' and 'pdf' in request.files:
        uploaded_file = request.files['pdf']
        if uploaded_file and uploaded_file.filename.endswith('.pdf'):
            # Get the text content
            reader = PyPDF2.PdfReader(uploaded_file)
            pdf_text = ""
            for page in reader.pages:
                pdf_text += page.extract_text()
            
            # Store the text in session
            session['pdf_text'] = pdf_text
            
            # Your existing parsing code...
            company_name, customer, order_date, sales_person, rq_invoice, total_price, accessories_prices, upgrades_count, activations_count, ppp_present, imei_iccid_pairs, activation_fee_sum = extract_info_from_pdf(uploaded_file)
            
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
                'imei_iccid_pairs': imei_iccid_pairs
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
    
    if 'parsed_data' not in session or 'pdf_text' not in session:  # Add check for pdf_text
        return redirect(url_for('upload_pdf'))
    

    # Get logged in user's name (using name field, not username)
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT name FROM users WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    logged_in_user = user[0] if user else None
    
    if request.method == 'POST':
        print(f"Current user_id in session: {session.get('user_id')}")
        
        company_name = request.form.get('company_name', 'N/A')
        customer = request.form.get('customer', 'N/A')
        order_date = request.form.get('order_date', 'N/A')
        sales_person = request.form.get('sales_person', 'N/A')
        rq_invoice = request.form.get('rq_invoice', 'N/A')
        total_price = float(request.form.get('total_price', 0))
        accessories_prices = request.form.get('accessories_prices', '')
        upgrades_count = int(request.form.get('upgrades_count', 0))
        activations_count = int(request.form.get('activations_count', 0))
        ppp_present = 'ppp_present' in request.form
        activation_fee_sum = float(request.form.get('activation_fee_sum', 0))

        user_id = session.get('user_id')
        if not user_id:
            print("No user_id found in session!")
            return redirect(url_for('login'))

        db = get_db()
        cursor = db.cursor()
        
        print(f"About to insert receipt for user_id: {user_id}")
        print(f"Data to insert: {(company_name, customer, order_date, sales_person, rq_invoice, total_price, accessories_prices, upgrades_count, activations_count, ppp_present, activation_fee_sum, user_id)}")
        
        cursor.execute('''
            INSERT INTO parsed_receipts (
                company_name, customer, order_date, sales_person, rq_invoice, 
                total_price, accessory_prices, upgrades_count, activations_count, 
                ppp_present, activation_fee_sum, user_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            company_name, customer, order_date, sales_person, rq_invoice, 
            total_price, accessories_prices, upgrades_count, activations_count, 
            ppp_present, activation_fee_sum, user_id
        ))
        
        db.commit()
        
        cursor.execute("SELECT * FROM parsed_receipts WHERE user_id = ? ORDER BY id DESC LIMIT 1", (user_id,))
        last_insert = cursor.fetchone()
        print(f"Last inserted record: {last_insert}")
        
        session.pop('parsed_data', None)
        return redirect(url_for('view_receipts'))
    
    if request.method == 'GET':
        pdf_text = session['pdf_text']  # Get the stored PDF text
        
        def find_imei_iccid_pairs(text):
            imei_iccid_pairs = []
            lines = text.split('\n')
            current_imei = None
            current_device = {}
            
            for line in lines:
                if 'IMEI:' in line:
                    current_imei = line.split('IMEI:')[1].strip()
                    current_device = {'imei': current_imei}
                elif 'ICCID:' in line and current_imei:
                    current_iccid = line.split('ICCID:')[1].strip()
                    current_device['iccid'] = current_iccid
                    if current_device not in imei_iccid_pairs:
                        imei_iccid_pairs.append(dict(current_device))
                    current_device = {}
                    current_imei = None
            
            return imei_iccid_pairs

        parsed_data = session['parsed_data']
        parsed_data['imei_iccid_pairs'] = find_imei_iccid_pairs(pdf_text)
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

    if user and user[7] == 1:
        # Admin can see all receipts
        cursor.execute("SELECT * FROM parsed_receipts")
    else:
        # Non-admin users only see their own receipts
        cursor.execute("SELECT * FROM parsed_receipts WHERE user_id = ?", (session['user_id'],))

    receipts = cursor.fetchall()

    return render_template('view_receipts.html', receipts=receipts)

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
                COALESCE(SUM(parsed_receipts.total_price), 0) as total_accessories
            FROM 
                users
            LEFT JOIN 
                parsed_receipts ON users.id = parsed_receipts.user_id
            GROUP BY 
                users.username, users.name
        ''')
    else:
        cursor.execute('''
            SELECT 
                users.username, 
                users.name,
                SUM(COALESCE(parsed_receipts.activations_count, 0)) as total_activations,
                SUM(COALESCE(parsed_receipts.upgrades_count, 0)) as total_upgrades,
                SUM(COALESCE(parsed_receipts.activations_count, 0) + COALESCE(parsed_receipts.upgrades_count, 0)) as total_devices,
                COALESCE(SUM(parsed_receipts.total_price), 0) as total_accessories
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
    
    # Calculate current tier
    current_tier = 1
    if accessories_total >= 1750:
        current_tier = 4
    elif accessories_total >= 1000:
        current_tier = 3
    elif accessories_total >= 750:
        current_tier = 2
    elif accessories_total >= 500:
        current_tier = 1

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
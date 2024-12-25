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


app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.permanent_session_lifetime = timedelta(minutes=15)

bcrypt = Bcrypt(app)
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

DATABASE = 'users.db'

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
            is_admin INTEGER DEFAULT 0
        );
    ''')

    # Create the parsed_receipts_new table
    db.execute('''
        CREATE TABLE IF NOT EXISTS parsed_receipts_new (
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
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    ''')

    # Copy the data from parsed_receipts into parsed_receipts_new
    db.execute('''
        INSERT INTO parsed_receipts_new (id, company_name, customer, order_date, sales_person, rq_invoice, total_price, accessory_prices, upgrades_count, activations_count, ppp_present, activation_fee_sum)
        SELECT id, company_name, customer, order_date, sales_person, rq_invoice, total_price, accessory_prices, upgrades_count, activations_count, ppp_present, activation_fee_sum FROM parsed_receipts;
    ''')

    # Drop the old parsed_receipts table
    db.execute('DROP TABLE IF EXISTS parsed_receipts;')

    # Rename parsed_receipts_new to parsed_receipts
    db.execute('ALTER TABLE parsed_receipts_new RENAME TO parsed_receipts;')

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
        accessory_prices = request.form['accessory_prices']
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
                session['user_id'] = user[1]
                
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

# Approve an account by user ID
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


# Reject (or delete) an account by user ID
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

# Logout route
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('admin', None)
    return redirect(url_for('login'))

# Function to extract info from PDF
def extract_info_from_pdf(pdf_file):
    reader = PyPDF2.PdfReader(pdf_file)
    pdf_text = ""
    
    for page in reader.pages:
        pdf_text += page.extract_text()
        
    # Regular expression patterns
    company_pattern = r"Smart Touch Wireless LLC\s*-\s*(.*?)(?:\n|\s*\()"
    customer_pattern = r"Customer\s*(.*?)(?:\n|\s*\()"
    order_date_pattern = r"Order Date\s*(\d{1,2}-\w{3}-\d{4}\s*\d{1,2}:\d{2}:\d{2}\s*\w*)"
    sales_person_pattern = r"Tendered By:\s*(.*?)(?:\n|$)"
    rq_invoice_pattern = r"RQ Invoice #\s*:\s*(\w+)"
    accessory_price_pattern = r"Item Total \$([\d]+\.[\d]{2})"

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
    accessory_prices = [round_up(float(price), 2) for price in re.findall(accessory_price_pattern, pdf_text.split('IMEI', 1)[0])]
    total_price = round_up(sum(accessory_prices), 2)

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
        activation_fee_sum)

# PDF upload page
@app.route('/upload', methods=['GET', 'POST'])
def upload_pdf():
    if 'logged_in' not in session:
        return redirect(url_for('login') + '?session_expired=true')

    if request.method == 'POST' and 'pdf' in request.files:
        uploaded_file = request.files['pdf']

        # Check if a file was selected
        if uploaded_file.filename == '':
            return "No selected file", 400

        # Check if the uploaded file is a PDF
        if uploaded_file and uploaded_file.filename.endswith('.pdf'):
            # Parse the PDF and extract the information
            company_name, customer, order_date, sales_person, rq_invoice, total_price, accessories_prices, upgrades_count, activations_count, ppp_present, activation_fee_sum = extract_info_from_pdf(uploaded_file)

            # Store the parsed data in the session for the confirmation page
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
                'activation_fee_sum': activation_fee_sum
            }

            # Redirect to the confirmation page
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
    
    # Check if parsed data exists in session
    if 'parsed_data' not in session:
        return redirect(url_for('upload_pdf'))
    
    if request.method == 'POST':
        # Retrieve the edited form data with .get() to handle missing keys
        company_name = request.form.get('company_name', 'N/A')
        customer = request.form.get('customer', 'N/A')
        order_date = request.form.get('order_date', 'N/A')
        sales_person = request.form.get('sales_person', 'N/A')
        rq_invoice = request.form.get('rq_invoice', 'N/A')
        total_price = float(request.form.get('total_price', 0))
        accessories_prices = request.form.get('accessories_prices', '')
        upgrades_count = int(request.form.get('upgrades_count', 0))
        activations_count = int(request.form.get('activations_count', 0))  # Provide a default of 0
        ppp_present = 'ppp_present' in request.form  # Checkbox returns True if checked
        activation_fee_sum = float(request.form.get('activation_fee_sum', 0))

        # Insert edited data into the database
        user_id = session['user_id']
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            INSERT INTO parsed_receipts (company_name, customer, order_date, sales_person, rq_invoice, total_price, 
                                         accessory_prices, upgrades_count, activations_count, ppp_present, activation_fee_sum, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            company_name, customer, order_date, sales_person, rq_invoice, total_price, accessories_prices,
            upgrades_count, activations_count, ppp_present, activation_fee_sum, user_id
        ))
        db.commit()
        
        # Clear the session data after saving to the database
        session.pop('parsed_data', None)
        
        return redirect(url_for('view_receipts'))
    
    # Retrieve the parsed data for display if it's a GET request
    parsed_data = session['parsed_data']
    
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
    # Ensure the user is logged in and is an admin
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    # Connect to the database
    db = get_db()
    cursor = db.cursor()

    # Aggregate activations, upgrades, and accessories for each user
    cursor.execute('''
        SELECT 
            users.username, 
            users.name,
            SUM(parsed_receipts.activations_count) AS total_activations,
            SUM(parsed_receipts.upgrades_count) AS total_upgrades,
            SUM(parsed_receipts.activations_count + parsed_receipts.upgrades_count) AS total_devices,
            SUM(parsed_receipts.accessory_prices) AS total_accessories
        FROM 
            users
        LEFT JOIN 
            parsed_receipts ON users.id = parsed_receipts.user_id
        GROUP BY 
            users.username, users.name
    ''')
    commission_data = cursor.fetchall()

    return render_template('commission.html', commission_data=commission_data)


if __name__ == '__main__':
    with app.app_context():
        init_db()  # Initialize the database tables
    app.run(debug=True)

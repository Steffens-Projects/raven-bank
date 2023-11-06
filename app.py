from flask import Flask, render_template, url_for, session, request, redirect, flash
import mysql.connector
from mysql.connector import Error
from dotenv import load_dotenv
import os
from werkzeug.security import check_password_hash, generate_password_hash
import boto3
from itsdangerous import URLSafeTimedSerializer, SignatureExpired


# GENERAL SETUP TASKS
# ==========================================
load_dotenv('variables.env')
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
app.config['AWS_ACCESS_KEY_ID'] = os.getenv('AWS_ACCESS_KEY_ID')
app.config['AWS_SECRET_ACCESS_KEY'] = os.getenv('AWS_SECRET_ACCESS_KEY')
app.config['AWS_REGION_NAME'] = os.getenv('AWS_REGION_NAME')
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])





# UTILITY FUNCTIONS
# =========================================

def database_connection():
    connection = None
    try:
        connection = mysql.connector.connect(
            host="host.docker.internal",
            user="root",
            passwd=os.getenv("MYSQL_ROOT_PASSWORD"),
            database=os.getenv("MYSQL_DATABASE")
        )
        print("Database connection: SUCCESS!")
    except Error as err:
        print(f"Error: {err}")
    return connection


@app.after_request
def add_header(response):
    # Disable caching for all responses
    response.headers['Cache-Control'] = 'no-store'
    return response


def generate_password_reset_token(email):
    return serializer.dumps(email, salt='email-reset')

# ROUTE FUNCTIONS
# ==========================================
@app.route('/')
def index():
    return render_template("index.html")

@app.route('/application', methods=['GET', 'POST'])
def application():
    if 'username' not in session:
        flash('You must be logged in to view this page.', 'warning')
        return redirect(url_for('login'))
    
    current_balance = 500  # This should be retrieved from your database

    if request.method == 'POST':
        if 'deposit' in request.form:
            pass
        elif 'withdraw' in request.form:
            pass
        elif 'transfer' in request.form:
            pass
    return render_template('application.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('_flashes', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = database_connection()
        if conn is not None:
            cursor = conn.cursor(dictionary=True)
            try:
                cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
                user_record = cursor.fetchone()
                cursor.fetchall()

                if user_record and check_password_hash(user_record['password'], password):
                    session['username'] = user_record['username']
                    flash('You have logged in succesfully!', 'success')
                    return redirect(url_for('application'))
                else:
                    flash('Login failed. Try again.', 'danger')
            except mysql.connector.Error as err:
                flash(f'Error: {err}', 'danger')
            finally:
                cursor.close()
                conn.close()

    return render_template('login.html')

@app.route('/create_account', methods=['GET', 'POST'])
def create_account():
    if request.method =='POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if len(username) < 7 or not username.isalnum():
            flash('Username must be atleast 7 characters and only contain letters and numbers', 'danger')
            return render_template('create_account.html')
        if len(password) < 8:
            flash('Password must be atleast 8 characters', 'danger')
            return render_template('create_account.html')

        hashed_password = generate_password_hash(password)

        conn = database_connection()
        cursor = conn.cursor()
        try:
            
            cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
            user_record = cursor.fetchone()
            cursor.fetchall()
            if user_record:
                flash('Email is already in use.', 'danger')
                return render_template('create_account.html')


            cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
            user_record = cursor.fetchone()
            cursor.fetchall()
            if user_record:
                flash('Username is already taken.', 'danger')
                return render_template('create_account.html')

            cursor.execute('INSERT INTO users (username, email, password) VALUES (%s, %s, %s)', (username, email, hashed_password))
            conn.commit()

            flash('Account created succesfully', 'success')
            return redirect(url_for('index'))
        except mysql.connector.Error as err:
            flash(f'Error: {err}', 'danger')
        finally:
            cursor.close()
            conn.close()

    return render_template('create_account.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method=='POST':
        email = request.form['email']
        token = generate_password_reset_token(email)
        reset_url = url_for('reset_with_token', token=token, _external=True)

        ses_client = boto3.client(
            'ses',
            aws_access_key_id=app.config['AWS_ACCESS_KEY_ID'],
            aws_secret_access_key=app.config['AWS_SECRET_ACCESS_KEY'],
            region_name=app.config['AWS_REGION_NAME']
        )

        ses_client.send_email(
            Source=os.getenv("VERIFIED_SES_EMAIL"),
            Destination={'ToAddresses': [email]},
            Message={
                'Subject': {'Data': 'Raven Bank Password Reset'},
                'Body': {
                    'Text': {
                        'Data': 'Please click the link to reset password: {}'.format(reset_url)
            }}}
            )
        flash('Please check your email for a password reset link.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_password.html')

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    try:
        email = serializer.loads(token, salt='email-reset', max_age=3600)
    except SignatureExpired:
        return '<h1>The token is expired!</h1>'
    
    if request.method=='POST':
        password=request.form['password']
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template('reset_with_token.html', token=token)
        hashed_password = generate_password_hash(password)
        
        try:
            conn = database_connection()
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET password = %s WHERE email = %s', (hashed_password, email))
        except Exception as e:
           flash('An error occurred while updating your password.', 'danger') 
        finally:
            cursor.close()
            conn.close()
        flash('Your password has been updated!', 'success')
        return redirect(url_for('login'))
    return render_template('reset_with_token.html', token=token)

if __name__ == "__main__":
    app.run(debug=True)
from flask import Flask, render_template, request, redirect, url_for, session
import pymysql.cursors, re, hashlib


app = Flask(__name__)
app.secret_key = '45678923424bh4h4h2hh4h4444hj111'
connection = pymysql.connect(host='localhost',
                             user='root',
                             password='Prince26',
                             database='flaskapp',
                             cursorclass=pymysql.cursors.DictCursor)



@app.route('/pythonlogin/', methods=['GET', 'POST'])
def login():
    # Output message if something goes wrong...
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username =request.form['username']
        password  = request.form['password']
        hash =  password +app.secret_key
        hash =  hashlib.sha1(hash.encode())
        password =  hash.hexdigest()
        with connection:
            with connection.cursor() as cursor:
                sql = 'SELECT * FROM accounts WHERE username = %s AND password = %s'
                cursor.execute(sql, (username,password,))
                result = cursor.fetchone()
                # return result
            if result:
                # Create session data, we can access this data in other routes
                session['loggedin'] = True
                session['id'] = result['id']
                session['username'] = result['username']
                    # Redirect to home page
                return '<script>alert("logged in");</script>'
            else:
                    # Account doesnt exist or username/password incorrect
                msg = 'Incorrect username/password!'
            # Show the login form with message (if any)
    return render_template('index.html', msg='')

@app.route('/pythonlogin/register', methods=['GET', 'POST'])
def register():
    # Output message if something goes wrong...
    msg = ''
    # Check if "username", "password" and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        with connection:
            with connection.cursor() as cursor:
                sql = 'SELECT * FROM accounts WHERE username = %s'
                cursor.execute(sql, (username,))
                account = cursor.fetchone()
                if account:
                    msg = 'Account already exists!'
                elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                    msg = 'Invalid email address!'
                elif not re.match(r'[A-Za-z0-9]+', username):
                    msg = 'Username must contain only characters and numbers!'
                elif not username or not password or not email:
                    msg = 'Please fill out the form!'
                else:
                    # Hash the password
                    hash = password + app.secret_key
                    hash = hashlib.sha1(hash.encode())
                    password = hash.hexdigest()
                    # Account doesn't exist, and the form data is valid, so insert the new account into the accounts table
                    cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s)', (username, password, email,))
                connection.commit()
                msg = 'You have successfully registered!'
                # redirect(url_for("/pythonlogin",next=request.endpoint))

    elif request.method == 'POST':
        # Form is empty... (no POST data)
        msg = 'Please fill out the form!'
    # Show registration form with message (if any)
    return render_template('register.html', msg=msg)
from flask import Flask, render_template, request, redirect, session, flash
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
import re
app = Flask(__name__)
app.secret_key='ASFHWEIhsdjfqwbfiuw98scjk9@$@'
bcrypt = Bcrypt(app)


# our index route will handle rendering our form
@app.route('/')
def index():
    return render_template("index.html")

@app.route('/process', methods=['POST'])
def results():
    print("Got Post Info")
    print(str(request.form))
    
    is_valid = True

    if len(request.form['fname']) < 1:
        flash("This field is required", 'fname')
        is_valid = False
    elif len(request.form['fname']) < 2:
        flash("Please enter a first name", 'fname')
        is_valid = False
    elif not re.match("^[a-zA-Z]+(?:_[a-zA-Z]+)?$", request.form['fname']):
        flash("The first name must be letters only", 'fname')
        is_valid = False

    if len(request.form['lname']) < 1:
        flash("This field is required", 'lname')
        is_valid = False
    elif len(request.form['lname']) < 2:
        flash("The last name needs to be at least two characters", 'lname')
        is_valid = False
    elif not re.match("^[a-zA-Z]+(?:_[a-zA-Z]+)?$", request.form['lname']):
        flash("The last name must be letters only", 'lname')
        is_valid = False
    
    if len(request.form['email']) < 1:
        flash("This field is required", 'email')
        is_valid = False
    elif len(request.form['email']) < 2:
        flash("The email address should be at least two characters", 'email')
        is_valid = False
    
    EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
    if not EMAIL_REGEX.match(request.form['email']):    # test whether a field matches the pattern
        print('email is not valid')
        flash("The email address is not valid", 'email')
        is_valid = False
    else:
        mysql = connectToMySQL('loginRegistration')
        query = "SELECT email FROM Users;"
        emails = mysql.query_db(query)
        print('emails is '+str(emails))
        for e in emails:
            print('e is '+str(e))
            if e['email'] == str(request.form['email']):
                flash("The email address is already being used", 'email')
                is_valid = False
    
    if len(request.form['password']) < 1:
        flash("This field is required", 'pwd')
        is_valid = False
    if len(request.form['confirm']) < 1:
        flash("This field is required", 'confirm')
        is_valid = False
    elif request.form['password'] != request.form['confirm']:
        flash("The passwords do not match", 'pwd')
        is_valid = False
    
    PWD_REGEX = re.compile(r'(?=\D*\d)(?=[^A-Z]*[A-Z])(?=[^a-z]*[a-z])[A-Za-z0-9]{10,}$')
    if not PWD_REGEX.match(request.form['password']):    # test whether a field matches the pattern
        print('The password must contain at least 1 digit, 1 uppercase letter, and 1 lowercase letter, and be greater than 10 characters')
        flash("The password must contain at least 1 digit, 1 uppercase letter, and 1 lowercase letter, and be greater than 10 characters", 'pwd')
        is_valid = False
        
    if is_valid:
        pw_hash = bcrypt.generate_password_hash(request.form['password'])
        mysql = connectToMySQL('loginRegistration')
        query = "INSERT INTO Users (first_name, last_name, email, password) VALUES (%(fname)s, %(lname)s, %(email)s, %(pwd)s);"
        data = {"fname": request.form['fname'],
                "lname": request.form['lname'],
                "email": request.form['email'],
                "pwd": pw_hash
        }
        print('query is '+str(query))
        new_id = mysql.query_db(query, data)
        flash("DB successfully added! New ID is "+str(new_id), 'regis')
        session['id'] = new_id
        return redirect('/success')
    else:
        print("Something on the form was not valid")

    return redirect('/')

@app.route('/login', methods=['post'])
def login():
    # do stuff for login

    mysql = connectToMySQL('loginRegistration')
    query = "SELECT * FROM Users WHERE email = '"+str(request.form['email'])+"';"
    print('SELECT query is '+query)
    res = mysql.query_db(query)
    print('result is '+str(res))

    if not res:
        flash("You could not be logged in", 'logout')
        return redirect('/')

    # pw_hash = bcrypt.generate_password_hash(request.form['password'])
    print("request.form[password] is "+str(request.form['password']))
    print("res[0][password] is "+str(res[0]['password']))

    if bcrypt.check_password_hash(res[0]['password'], request.form['password']):
        print("we passed the password validation")
        print("res[0][email] is "+str(res[0]['email']))
        print("request.form[email] is "+str(request.form['email']))
        if res[0]['email'] != request.form['email']:
            flash("You could not be logged in", 'logout')
            return redirect('/')

    first_name = res[0]['first_name']

    if 'id' in session:
        id = session['id']
    else:
        session['id'] = res[0]['id']

    return render_template('result.html', fname=first_name)

@app.route('/success', methods=['get', 'post'])
def success():
    if 'id' in session:
        id = session['id']
    else:
        flash("You must log in to enter this website", 'logout')
        return redirect('/')

    mysql = connectToMySQL('loginRegistration')
    query = "SELECT * FROM Users WHERE id = "+str(id)+";"
    print('SELECT query is '+query)
    res = mysql.query_db(query)
    print('result is '+str(res))
    first_name = res[0]['first_name']
    flash("You've been successfully registered", 'success')

    return render_template('result.html', fname=first_name)
    
@app.route('/logout', methods=['GET','POST'])
def search():
    print("logout")
    
    session.clear()
    flash('You have been logged out', 'logout')

    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)
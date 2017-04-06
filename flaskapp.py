
from flask import Flask, flash, redirect, render_template, url_for, send_from_directory, request, jsonify, session, abort
from werkzeug import secure_filename
from wtforms import Form, TextField, TextAreaField, validators, StringField, SubmitField
import mimetypes
from flask.ext.wtf import Form
from passlib.hash import sha256_crypt
import MySQLdb
from MySQLdb import escape_string as thwart
import subprocess
import gc
import os
from subprocess import PIPE, Popen
import re
import random, struct
from Crypto.Cipher import AES
import hashlib
from flask import Markup
import os.path
from flask_sslify import SSLify
import config
from nocache import nocache
from datetime import timedelta
 
app = Flask(__name__)
#sslify = SSLify(app)

#Database Connection. Security Feature: Getting secrets from different file
db = MySQLdb.connect(config.host,  
                     config.user,        
                     config.passwd,  
                     config.db)        
cur = db.cursor()

#Security Feature: Max Password attempts counter
login_failed = 0

#Secret Key for session.
app.secret_key = config.secret_key_file


#Secret Key, password, and initialization vector for encrypting file contents and storing on database.
password = config.enc_password
key = config.key
IV = config.IV           # Initialization vector
mode = config.mode


#Security Feature: Regex for username and password
userreg = config.user_reg
passreg = config.user_passv

#Registration page
@app.route('/register', methods=["GET","POST"])
@nocache
def register_page():
    error = ''
    try:
            username = request.form['user']
            password = request.form['password']
            if (re.match(userreg,username) and re.match(passreg,password)):
                hash = sha256_crypt.encrypt(password)
                x = cur.execute("SELECT * FROM user_table WHERE user_name = %s", (username,))
                if int(x) > 0:
                    return 'User Name taken pls try again.'
                else:
                    cur.execute("INSERT INTO user_table (user_name,password) VALUES(%s,%s)", (username, hash))
                    db.commit()
                    db.close()
                return 'Registered'
            else:
		return 'UserName:2-15 charecters consisting of letter or digits and optional -or_. Password: 6-18 charecters consisting of letter or digits and optional -or_'
    except Exception as e:
        return(str(e))

#Welcome Screen	   
@app.route('/')
@nocache
def home():
    return render_template('welcome.html')

#Security Feature: allowing only specefic filenames like .cpp, .php etc
def allowed_file(file_name):
    return '.' in file_name and \
           file_name.rsplit('.', 1)[1] in config.ALLOWED_EXTENSION

#Secure Login Function with max attempts, regex and session. 
#Storing hashed passwords on database. 
@app.route('/login', methods=["GET","POST"])
def login():
  error = ''
  global login_failed
  if(login_failed < 2):
    if request.method == 'POST':
        username_form  = request.form['username']
        password_form  = request.form['password']
        if(cur.execute("SELECT * FROM user_table WHERE user_name = %s",  (username_form,))):
            cur.execute("SELECT password FROM user_table WHERE user_name = %s", (username_form,))
            hash_stored = cur.fetchone()
            if(sha256_crypt.verify(password_form, hash_stored[0])):
                print ('query executed')
                session['logged_in'] = True
                session['username'] = username_form
		session.permanent = True
		app.permanent_session_lifetime = timedelta(seconds=300)
                return render_template('upload_db.html', username = session['username'])
            else:
                login_failed = login_failed+1
                error+= "Invalid Password"
                return render_template('welcome.html', error = error)
        else:
            error+= "Invalid Username. Login Again"
            return render_template('welcome.html', error = error)
    else:
        error+= "Failed. Login Again"
        return render_template('welcome.html', error = error)
  else:
	login_failed = 0
	error = 'You have exceeded maximum attempts for failed login. Locked Out. Try agin after 30 mins'
        return render_template('welcome.html', error = error)
	
	

		
#Secure uploader: file encryption, sessions, session timeout, specefic files allowed. AES Encryption used.
#Secure filename of flask used.	
@app.route('/uploader', methods = ['GET', 'POST'])
def upload_file():
 error = ''
 if('username' in session):
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    if request.method == 'POST':
        file = request.files['userfile']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
	    check = config.temp_path_main+filename
            file_contents = file.read()
            iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
            if len(file_contents) == 0:
                return 'Empty File'
            elif len(file_contents) >= 1000000:
                return 'File too large'
            elif len(file_contents) % 16 != 0:
                file_contents += ' ' * (16 - len(file_contents) % 16)
            enc_content = (encryptor.encrypt(file_contents))
            if(cur.execute("SELECT uid FROM user_table WHERE user_name = %s", (session['username'],))):
                uid = cur.fetchone()
                if(cur.execute("INSERT INTO file_upload (uid,f_name,f_content) VALUES(%s,%s,%s)", (uid[0],filename,enc_content))):
                    db.commit()
                    final_results = ''
                    file_contents = ''
                    fetched_file = filename
                    a,b = fetched_file.split(".")
                    str_class = "class"
                    str_cpp = "cpp"
                    str_py = "py"
                    str_php = "php"
                    if(cur.execute("SELECT f_content FROM file_upload WHERE f_name = %s", (filename,))):
                        f_content = cur.fetchone()
                        file_contents+=f_content[0]
                        decryptor = AES.new(key, AES.MODE_CBC, IV)
                        dec_content = (decryptor.decrypt(file_contents))
                        temp_file = config.temp_path_main + filename
                        with open(temp_file, "w") as f:
                            f.write(dec_content)
                            f.close()
                        if(b == str_class):
                            path = config.temp_path
                            results=subprocess.Popen(path, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                            command = "findbugs "+path+filename
                            results=subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate()[0]
                            result_file = config.analysis_path+a+".txt"
                            with open(result_file, "w") as f:
                                f.write(str(results))
                                f.close()
                            with open(result_file, "r") as f:
                                final_results+=f.read()
                                f.close()
                            if len((final_results)) % 16 != 0:
                                final_results += ' ' * (16 - len((final_results)) % 16)
                            enc_results = (encryptor.encrypt(final_results))
                            if(cur.execute("UPDATE file_upload SET f_results = %s WHERE uid = %s", (enc_results,uid[0]))):
                                db.commit()
                            return render_template('render_results.html', result = results)
                        elif(b == str_cpp):
                            path = config.temp_path
                            results=subprocess.Popen(path, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                            command = "flawfinder "+path+filename
                            results=subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate()[0]
                            result_file = config.analysis_path+a+".txt"
                            with open(result_file, "w") as f:
                                f.write(str(results))
                                f.close()
                            with open(result_file, "r") as f:
                                final_results+=f.read()
                                f.close()
                            if len((final_results)) % 16 != 0:
                                final_results += ' ' * (16 - len((final_results)) % 16)
                            enc_results = (encryptor.encrypt(final_results))
                            if(cur.execute("UPDATE file_upload SET f_results = %s WHERE uid = %s", (enc_results,uid[0]))):
                                db.commit()
                            return render_template('render_results.html', result = results)
                        elif(b == str_php):
                            path = config.temp_path
                            results=subprocess.Popen(path, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                            command = "phpcs "+path+filename
                            results=subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate()[0]
			    if check in results:
				final_results.replace(check, "***")
                            result_file = config.analysis_path+a+".txt"
                            with open(result_file, "w") as f:
                                f.write(str(results))
                                f.close()
                            with open(result_file, "r") as f:
                                final_results+=f.read()
                                f.close()
                            if len((final_results)) % 16 != 0:
                                final_results += ' ' * (16 - len((final_results)) % 16)
                            enc_results = (encryptor.encrypt(final_results))
                            if(cur.execute("UPDATE file_upload SET f_results = %s WHERE uid = %s", (enc_results,uid[0]))):
                                db.commit()
                            return render_template('render_results.html', result = results)
                        elif(b == str_py):
                            path = config.temp_path
                            command = "pylint "+path+filename
                            results=subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate()[0]
			    if check in str(results):
				final_results.replace(check, "***")
                            result_file = config.analysis_path+a+".txt"
                            with open(result_file, "w") as f:
                                f.write(str(results))
                                f.close()
                            with open(result_file, "r") as f:
                                final_results+=f.read()
                                f.close()
                            if len((final_results)) % 16 != 0:
                                final_results += ' ' * (16 - len((final_results)) % 16)
                            enc_results = (encryptor.encrypt(final_results))
                            if(cur.execute("UPDATE file_upload SET f_results = %s WHERE uid = %s", (enc_results,uid[0]))):
                                db.commit()
                            return render_template('render_results.html', result = results)
                        else:
                            return 'File type cannot be analyzed. Bye Bye.'
                    else:
                        return 'File doe not exist. Bye Bye.'
        else:
	       return 'File Type not supported. Please try again!'
 else:
     error = 'Session Time Out. Please login again.'
     return render_template('welcome.html', error = error)
 

#Secure Viewing function. Fetching results of analysis.
@app.route('/viewer', methods = ['GET', 'POST'])
def view_file():
 error = ''
 if('username' in session):
    f_list = ''
    if(cur.execute("SELECT uid FROM user_table WHERE user_name = %s", (session['username'],))):
        uid = cur.fetchone()
        if(cur.execute("SELECT f_name FROM file_upload WHERE uid = %s", (uid[0],))):
            rows = cur.fetchall()
            for row in rows:
                f_list+=row[0]
                f_list+="<a href = '/view_results/" + row[0] + " " "'>StaticAnalysisResults</a>"
                f_list+="<br>"
    return Markup('''<!DOCTYPE html><html><head><!-- Latest compiled and minified CSS -->
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">

    <!-- Optional theme -->
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap-theme.min.css" integrity="sha384-rHyoN1iRsVXV4nD0JutlnGaslCJuC7uwjduW9SVrLvRYooPp2bWYgmgJQIXwl/Sp" crossorigin="anonymous">

    <!-- Latest compiled and minified JavaScript -->
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js" integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" crossorigin="anonymous"></script></head>
    <body>
    <h1>Analysis Results</h1>
    <br>
    <div class="row">
    <div class="col-lg-6">
    <div class="input-group"><br><br><br><br><table><td>''' + f_list + '''</td></table></div></div></div></body></html>''')
 else:
     error = 'Session Time Out. Please login again.'
     return render_template('welcome.html', error = error)

						
						
#Secure Viewing of files. Implemented asynchronous functionality. 
@app.route('/view_results/<file_name>')
def analyze_file(file_name):
 error = ''
 if('username' in session):
  session.modified = True
  if(session['logged_in']):
     final_results = ''
     file_contents = ''
     fetched_file = file_name
     a,b = fetched_file.split(".")
     result_file = config.analysis_path+a+".txt"
     if(os.path.isfile(result_file)):
         with open(result_file, "r") as f:
             final_results+=f.read()
             f.close()
         return render_template('render_results.html', result = final_results)
     else:
         return 'Analysis results does not exist. Bye Bye.'
  else:
      return 'Please have the courtesy to login.!!'
 else:
     error = 'Session Time Out. Please login again.'
     return render_template('welcome.html', error = error)
			

@app.route('/viewer/<analysis>')
def analyzed_file(analysis): 
  error = ''
  if('username' in session):
     return send_from_directory(app.config['UPLOAD_FOLDER'],
                               analysis)
  else:
     error = 'Session Time Out. Please login again.'
     return render_template('welcome.html', error = error)


@app.after_request
def remove_if_invalid(response):
    if "__invalidate__" in session:
        response.delete_cookie(app.session_cookie_name)
    return response

#Logout function with cache clearance. 
@app.route('/logout', methods=['GET', 'POST'])
@nocache
def logout():
 if 'username' in session:
    session.pop('username', None)
    session.clear()
    session["__invalidate__"] = True
    #print("****** logout" + session['username'])
    return render_template('welcome.html')

	  
if __name__ == "__main__":
	app.secret_key = config.secret_key_file
	context = SSL.Context(SSL.SSLv3_METHOD)
	app.run(use_reloader=True, host=<aws instance>,ssl_context = context,debug=False)

from flask import Flask, render_template, request, redirect, session
from auth import register_user, validate_user
from db import init_db

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this in production!

# Initialize database
init_db()

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        if validate_user(username, password):
            session['username'] = username
            return redirect('/')
        else:
            return render_template('login.html', error="Invalid username or password.")
    return render_template('login.html')

# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        if register_user(username, password):
            return redirect('/login')
        else:
            return render_template('register.html', error="User already exists. Please try another username.")
    return render_template('register.html')

# Logout Route
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/login')

# Protected Homepage (Index)
@app.route('/')
def home():
    if 'username' not in session:
        return redirect('/login')
    return render_template('index.html', username=session['username'])

# Start the Flask server
if __name__ == '__main__':
    app.run(debug=True)

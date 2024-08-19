from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/forum')
def forum():
    return render_template('forum.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Process login form data
        email = request.form['email']
        password = request.form['password']
        # Here you would typically authenticate the user
        return redirect(url_for('forum'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        return redirect(url_for('forum'))
    return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)


from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from datetime import datetime
from flask_migrate import Migrate
import locale
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, Length
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key_here'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class Thread(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Tråd {self.title}>'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    join_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    threads = db.relationship('Thread', backref='author', lazy=True)
    is_admin = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<User {self.username}>'
    

class ThreadForm(FlaskForm):
    title = StringField('Titel', validators=[DataRequired(), Length(min=3, max=150)])
    content = TextAreaField('Innehåll', validators=[DataRequired()], render_kw={"rows": 20})
    submit = SubmitField('Skapa Tråd')
    

class LoginForm(FlaskForm):
    email = StringField('E-postadress', validators=[DataRequired(), Email()])
    password = PasswordField('Lösenord', validators=[DataRequired()])
    submit = SubmitField('Logga in')


class RegistrationForm(FlaskForm):
    username = StringField('Användarnamn', validators=[DataRequired(), Length(min=3, max=150)])
    email = StringField('E-postadress', validators=[DataRequired(), Email()])
    password = PasswordField('Lösenord', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Registrera dig')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/forum')
@login_required
def forum():
    threads = Thread.query.order_by(Thread.timestamp.desc()).all()
    return render_template('forum.html', threads=threads)


@app.route('/threads/<int:thread_id>', methods=['GET'])
def view_thread(thread_id):
    thread = Thread.query.get_or_404(thread_id)
    return render_template('view_thread.html', thread=thread)

@app.route('/threads/<int:thread_id>/delete', methods=['POST'])
@login_required
def delete_thread(thread_id):
    thread = Thread.query.get_or_404(thread_id)

    if current_user.id != thread.author_id and not current_user.is_admin:
        flash('Du har inte behörighet att ta bort denna tråd.', 'danger')
        return redirect(url_for('forum'))
    
    db.session.delete(thread)
    db.session.commit()
    flash('Tråden har tagits bort.', 'success')
    return redirect(url_for('forum'))



@app.route('/threads/new', methods=['GET', 'POST'])
@login_required
def new_thread():
    form = ThreadForm()
    if form.validate_on_submit():
        thread = Thread(title=form.title.data, content=form.content.data, author=current_user)
        db.session.add(thread)
        db.session.commit()
        flash('Tråden skapades', 'success')
        return redirect(url_for('forum'))
    return render_template('new_thread.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('forum'))
        else:
            flash("Fel E-Post address eller lösenord, Försök igen", 'danger')
        
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Det finns redan ett konto registrerat med denna e-postadress.", 'warning')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash("Registrering lyckades. Du kan nu logga in.", 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"Det uppstod ett problem att lägga till din data: {str(e)}", 'danger')
        
    return render_template('register.html', form=form)


@app.route('/profile')
def profile():
    threads = Thread.query.filter_by(author_id=current_user.id).all()
    return render_template('profile.html', threads=threads)

migrate = Migrate(app, db)

locale.setlocale(locale.LC_TIME, 'sv_SE.UTF-8')



if __name__ == '__main__':
    with app.app_context():
        user = User.query.filter_by(username='admin').first()
        if user:
            user.is_admin = True
            db.session.commit()
            print(f"User {user.username} has been set as admin.")
        else:
            print("Admin user not found")
    app.run(debug=True, host='0.0.0.0', port=8080)

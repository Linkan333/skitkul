from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from datetime import datetime
from flask_migrate import Migrate
import locale
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, BooleanField
from wtforms.validators import DataRequired, Email, Length
from flask_wtf.csrf import CSRFProtect
from flask_wtf.file import FileField, FileAllowed
import os
from werkzeug.utils import secure_filename


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key_here'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
csrf = CSRFProtect(app)




class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    thread_id = db.Column(db.Integer, db.ForeignKey('thread.id'))

    user = db.relationship('User', back_populates='notifications')
    thread = db.relationship('Thread')

    def __repr__(self):
        return f'<Notifikation {self.message}>'


class Reply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    thread_id = db.Column(db.Integer, db.ForeignKey('thread.id'), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    author = db.relationship('User', backref='replies')

    def __repr__(self):
        return f'<Svar {self.content[:20]}...>'

class Thread(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


    replies = db.relationship('Reply', backref='thread', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Tråd {self.title}>'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    profile_picture = db.Column(db.String(150), nullable=True)
    join_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    threads = db.relationship('Thread', backref='author', lazy=True)
    is_admin = db.Column(db.Boolean, default=False)
    notifications = db.relationship('Notification', back_populates='user', lazy='dynamic')


    def __repr__(self):
        return f'<User {self.username}>'
    

class SecurityandIntegrity(FlaskForm):
    show_email = BooleanField('Låt andra användare se din E-Post.', default=False)
    allow_interactions = BooleanField('Låt andra användare integrera med dig.', default=False)
    allow_messages = BooleanField('Låt andra användare skicka meddelanden till dig.', default=False)
    submit = SubmitField('Spara ändringar')

class ReplyForm(FlaskForm):
    content = TextAreaField('Innehåll', validators=[DataRequired()], render_kw={"rows": 5})
    submit = SubmitField('Svara')

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

class UpdateProfileForm(FlaskForm):
    profile_picture = FileField('Byt profilbild', validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Uppdatera')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/logout')
@login_required
def logout():
    flash('Loggade ut!', 'warning')
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

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = UpdateProfileForm()  # Initialize the form
    if form.validate_on_submit():
        if form.profile_picture.data:
            picture_file = save_profile_picture(form.profile_picture.data)
            current_user.profile_picture = picture_file
            db.session.commit()
            flash('Din profilbild har uppdaterats.', 'info')
        return redirect(url_for('profile'))
    
    return render_template('edit_profile.html', form=form)



@app.route('/threads/<int:thread_id>', methods=['GET', 'POST'])
@login_required
def view_thread(thread_id):
    thread = Thread.query.get_or_404(thread_id)  # Fetch the thread to ensure it exists
    form = ReplyForm()

    if form.validate_on_submit():
        reply = Reply(content=form.content.data, author=current_user, thread=thread)
        db.session.add(reply)
        db.session.commit()

        if thread.author_id != current_user.id:
            print(f"Creating notification for user ID {thread.author_id}")
            notification = Notification(
                user_id=thread.author_id,
                message=f'{current_user.username} svarade på ditt inlägg {thread.title}',
                thread_id=thread.id
            )
            db.session.add(notification)
            db.session.commit()

        flash('Ditt svar har lagts till.', 'success')
        return redirect(url_for('view_thread', thread_id=thread.id))
    
    replies = Reply.query.filter_by(thread_id=thread.id).order_by(Reply.timestamp.asc()).all()

    if form.validate_on_submit():
        reply = Reply(content=form.content.data, author=current_user, thread=thread)
        db.session.add(reply)
        db.session.commit()
        flash('Ditt svar har lagts till.', 'success')
        return redirect(url_for('view_thread', thread_id=thread.id))

    return render_template('view_thread.html', thread=thread, form=form, replies=replies)


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
        flash('En tråd skapades', 'success')
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
            flash("Inloggning Lyckades omdirigerar sidan till forumet!", "success")
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
            flash("Du skapade ett konto, omdirigerar till login", 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"Det uppstod ett problem att lägga till din data: {str(e)}", 'danger')
        
    return render_template('register.html', form=form)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = UpdateProfileForm()
    if form.validate_on_submit():
        if form.profile_picture.data:
            picture_file = save_profile_picture(form.profile_picture.data)
            current_user.profile_picture = picture_file
            db.session.commit()
            flash('Din profilbild har uppdaterats.', 'info')
        return redirect(url_for('profile'))
    
    return render_template('profile.html', form=form)

def save_profile_picture(form_picture):
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = secure_filename(current_user.username + f_ext)
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)

    form_picture.save(picture_path)
    return picture_fn


@app.route('/threads/<int:thread_id>/reply', methods=['GET', 'POST'])
@login_required
def reply_thread(thread_id):
    thread = Thread.query.get_or_404(thread_id)
    form = ReplyForm()
    if form.validate_on_submit():
        reply = Reply(content=form.content.data, author=current_user, thread=thread)
        db.session.add(reply)
        db.session.commit()
        flash('Ditt svar har publicerats.', 'success')
        return redirect(url_for('view_thread', thread_id=thread.id))
    return render_template('reply_thread.html', thread=thread, form=form)



@app.route('/notifications/read_all')
@login_required
def read_all_notifications():
    notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).all()
    for notification in notifications:
        notification.is_read = True
    db.session.commit()
    return redirect(url_for('home'))



locale.setlocale(locale.LC_TIME, 'sv_SE.UTF-8')

migrate = Migrate(app, db)

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

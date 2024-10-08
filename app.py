from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from datetime import datetime
from flask_migrate import Migrate
import locale
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, BooleanField, ValidationError
from wtforms.validators import DataRequired, Email, Length
from flask_wtf.csrf import CSRFProtect
from flask_wtf.file import FileField, FileAllowed
import os
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import secrets




app = Flask(__name__)



app.config['SECRET_KEY'] = '4d8bfddcaa38b430c632ea77d1c3b17c'


app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USERNAME'] = 'skitkulorg@gmail.com'
app.config['MAIL_PASSWORD'] = 'hbuv tara mich dkyc'
app.config['MAIL_DEFAULT_SENDER'] = 'skitkulorg@gmail.com'


mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
csrf = CSRFProtect(app)





def send_verification_mail(user_email):
    token = serializer.dumps(user_email, salt='email-confirm')
    confirm_url = url_for('confirm_email', token=token, _external=True)
    html = render_template('confirmation_email.html', confirm_url=confirm_url)
    subject = "Var snäll att verifiera din E-Postaddress"
    msg = Message(subject, recipients=[user_email], html=html)
    mail.send(msg)



class EmptyForm(FlaskForm):
    pass

class ChangeEmailForm(FlaskForm):
    new_email = StringField('Ny E-Postadress', validators=[DataRequired(), Email()])
    submit = SubmitField('Spara Ändringar')

class ChangeUsernameForm(FlaskForm):
    new_username = StringField('Nytt Användarnamn', validators=[DataRequired()])
    submit = SubmitField('Spara Ändringar')

    def validate_new_username(self, new_username):
        if new_username.data == current_user.username:
            flash("Hej Test2")
        
        existing_user = User.query.filter_by(username=new_username.data).first()
        if existing_user:
            print("Hej test3")



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
    is_active = db.Column(db.Boolean, default=False)
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
    submit = SubmitField('Spara Ändringar')
    new_email = StringField('Ny E-Postadress', validators=[DataRequired(), Email()])
    submit = SubmitField('Spara Ändringar')
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
def forum():
    threads = Thread.query.order_by(Thread.timestamp.desc()).all()
    return render_template('forum.html', threads=threads)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def edit_profile():
    # Instantiate both forms
    update_profile_form = UpdateProfileForm()
    change_email_form = ChangeEmailForm()
    change_username_form = ChangeUsernameForm()
    delete_form = EmptyForm()

    # Check if profile picture form was submitted
    if update_profile_form.validate_on_submit():
        if update_profile_form.profile_picture.data:
            picture_file = save_profile_picture(update_profile_form.profile_picture.data)
            current_user.profile_picture = picture_file
            db.session.commit()
            flash('Din profilbild har uppdaterats.', 'info')
        return redirect(url_for('edit_profile', form=form, username=username))

    return render_template('edit_profile.html', 
                            update_profile_form=update_profile_form,
                            change_email_form=change_email_form,
                            change_username_form=change_username_form,
                            delete_form=delete_form)

@app.route('/change_email', methods=['POST'])
@login_required
def change_email():
    change_email_form = ChangeEmailForm()
    if change_email_form.validate_on_submit():
        new_email = change_email_form.new_email.data
        existing_user = User.query.filter_by(email=new_email).first()
        if existing_user:
            flash('Denna E-Postadressen används redan av en annan användare', 'danger')
        else:
            current_user.email = new_email
            db.session.commit()
            flash('Din E-Postadress har uppdaterats', 'info')
        return redirect(url_for('edit_profile'))

    return redirect(url_for('edit_profile'))

@app.route('/change_username', methods=['POST'])
@login_required
def change_username():
    change_username_form = ChangeUsernameForm()
    if change_username_form.validate_on_submit():  
        new_username = change_username_form.new_username.data
        existing_user = User.query.filter_by(username=new_username).first()
        if existing_user:
            flash('Detta Användarnamnet används redan av en annan användare', 'danger')
        else:
            current_user.username = new_username
            db.session.commit()
            flash('Ditt användarnamn har uppdaterats', 'info')
        return redirect(url_for('edit_profile'))
    
    return redirect(url_for('edit_profile'))





@app.route('/threads/<int:thread_id>', methods=['GET', 'POST'])
def view_thread(thread_id):
    thread = Thread.query.get_or_404(thread_id)  
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

@app.route('/settings/<username>/delete', methods=['POST'])
@login_required
def delete_user(username):
    form = EmptyForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=username).first()

        if not user or current_user.username != user.username:
            flash('Du har inte behörighet att ta bort detta konto.', 'danger')
            return redirect(url_for('forum'))

        db.session.delete(user)
        db.session.commit()
        flash(f'Ditt konto {username} har tagits bort', 'info')
        return redirect(url_for('register'))

    return render_template('edit_profile.html', 
                           update_profile_form=UpdateProfileForm(),
                           change_email_form=ChangeEmailForm(),
                           change_username_form=ChangeUsernameForm(),
                           delete_form=form)


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
            #flash("Fel E-Post address eller lösenord, Försök igen", 'danger') 
            pass
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

            send_verification_mail(new_user.email)


            flash('En bekräftelse länk har skickats till {new_user.email} kontrollera din inkorg', 'info')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"Det uppstod ett problem att lägga till din data: {str(e)}", 'danger')
        
    return render_template('register.html', form=form)




@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=3600)
    except:
        flash("Bekräftelsen är ogiltig eller har gått ut", 'danger')
        return redirect(url_for('register'))
    
    user = User.query.filter_by(email=email).first_or_404()

    if user.is_active:
        flash('Ditt konto har redan bekräftats. Logga in', 'info')
        return redirect(url_for('login'))
    else:
        user.is_active = True
        db.session.commit()
        flash('Ditt konto är nu verifierat! Du kan nu logga in', 'success')
    
    return redirect(url_for('login'))



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
    
    return render_template('profile.html', form=form, user=current_user)

def save_profile_picture(form_picture):
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = secure_filename(current_user.username + f_ext)
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)

    form_picture.save(picture_path)
    return picture_fn

@app.route('/profile/<username>')
def user_profile(username):
    form = UpdateProfileForm()
    user = User.query.filter_by(username=username).first_or_404()
    threads = Thread.query.filter_by(author_id=user.id).all()
    return render_template('profile.html', user=user, threads=threads, form=form)



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

@app.route('/cookie-consent', methods=['POST'])
def cooie_consent():
    consent = request.json.get('consent')
    if consent:
        current_user.cookie_consent = consent
        db.session.commit()
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error'}), 400

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

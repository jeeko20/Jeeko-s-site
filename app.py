from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta, datetime
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from supabase import create_client, Client
import os
import uuid
from dotenv import load_dotenv

load_dotenv()  # Charge le .env

app = Flask(__name__)

# --------------------
# Config
# --------------------
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))
app.permanent_session_lifetime = timedelta(days=7)

# --------------------
# Supabase Storage
# --------------------
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
SUPABASE_BUCKET = "avatars"

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

def upload_avatar_to_supabase(file_content, filename):
    """Upload un fichier avatar vers Supabase Storage et retourne l'URL publique."""
    result = supabase.storage.from_(SUPABASE_BUCKET).upload(filename, file_content)
    if result:
        return f"{SUPABASE_URL}/storage/v1/object/public/{SUPABASE_BUCKET}/{filename}"
    return None

# --------------------
# DB
# --------------------
db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    profile = db.relationship('Profile', backref='user', uselist=False)

class Profile(db.Model):
    __tablename__ = "profile"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    bio = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    avatar_path = db.Column(db.String(200))
    complete_name = db.Column(db.String(100))
    email = db.Column(db.String(150))
    year_of_study = db.Column(db.String(50))

# --------------------
# Helpers
# --------------------
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --------------------
# Routes
# --------------------
@app.route('/')
def home():
    username = session.get('username')
    return render_template('index.html', username=username)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and user.is_active and check_password_hash(user.password, password):
            session.permanent = True
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if not username or not email or not password:
            flash('All fields are required.', 'danger')
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash('Email already taken.', 'danger')
        elif User.query.filter_by(username=username).first():
            flash('Username already taken.', 'danger')
        else:
            hash_password = generate_password_hash(password)
            new_user = User(username=username, email=email, password=hash_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Sign up successful! Please log in.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        flash('Please log in to access your profile.', 'warning')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    profile = user.profile

    if request.method == 'POST':
        complete_name = request.form['complete_name']
        email = request.form['email']
        bio = request.form['bio']
        avatar_file = request.files.get('avatar')
        year_of_study = request.form.get('year_of_study')   

        avatar_path = profile.avatar_path if profile else None
        if avatar_file and avatar_file.filename != '':
            if allowed_file(avatar_file.filename):
                avatar_filename = f"{uuid.uuid4().hex}_{secure_filename(avatar_file.filename)}"
                avatar_path = upload_avatar_to_supabase(avatar_file.read(), avatar_filename)
                if not avatar_path:
                    flash("Erreur lors de l'upload de l'image.", "danger")
                    return redirect(url_for("profile"))
            else:
                flash("Only image files (png, jpg, jpeg, gif) are allowed!", "danger")
                return redirect(url_for("profile"))

        if profile:
            profile.complete_name = complete_name
            profile.email = email
            profile.bio = bio
            profile.avatar_path = avatar_path
            profile.year_of_study = year_of_study
        else:
            new_profile = Profile(
                complete_name=complete_name,
                email=email,
                bio=bio,
                year_of_study=year_of_study,
                avatar_path=avatar_path,
                user_id=user.id
            )
            db.session.add(new_profile)

        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html', username=session.get('username'), user=user, profile=profile)

# --------------------
# Run
# --------------------
if __name__ == '__main__':
    app.run(debug=False)

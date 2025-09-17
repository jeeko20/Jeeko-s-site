from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import timedelta, datetime
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import os
import logging
from dotenv import load_dotenv
import cloudinary
import cloudinary.uploader
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

# --------------------
# Configuration de base
# --------------------
load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# 🔧 DATABASE_URL
database_url = os.environ.get("DATABASE_URL")
if not database_url:
    raise RuntimeError("❌ DATABASE_URL introuvable ! Vérifie ton fichier .env")
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

# --------------------
# SQLAlchemy avec pool limité à 5 connexions (plan gratuit Neon)
# --------------------
engine = create_engine(
    database_url,
    pool_size=5,       # max 5 connexions simultanées
    max_overflow=0,    # pas de connexions supplémentaires
    pool_timeout=30,   # attendre 30s si toutes les connexions occupées
)
db_session = scoped_session(sessionmaker(bind=engine))

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.environ.get("SECRET_KEY", "fallback_secret_key_change_in_prod")
app.permanent_session_lifetime = timedelta(days=7)

# SQLAlchemy Flask extension
db = SQLAlchemy(app)
db.session = db_session
migrate = Migrate(app, db)

# --------------------
# Cloudinary config
# --------------------
cloudinary.config(
    cloud_name=os.environ.get("CLOUDINARY_CLOUD_NAME"),
    api_key=os.environ.get("CLOUDINARY_API_KEY"),
    api_secret=os.environ.get("CLOUDINARY_API_SECRET")
)

# --------------------
# Modèles
# --------------------
class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
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

def upload_avatar_to_cloudinary(file):
    try:
        result = cloudinary.uploader.upload(file)
        return result.get("secure_url")
    except Exception as e:
        logger.error(f"Erreur Cloudinary: {e}")
        flash("Échec de l'upload de l'image.", "danger")
        return None

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
            flash('Connecté avec succès !', 'success')
            return redirect(url_for('home'))
        else:
            flash('Email ou mot de passe incorrect.', 'danger')
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        if not username or not email or not password:
            flash('Tous les champs sont obligatoires.', 'danger')
            return render_template('register.html')
        if User.query.filter_by(email=email).first():
            flash('Cet email est déjà utilisé.', 'danger')
        elif User.query.filter_by(username=username).first():
            flash('Ce nom d’utilisateur est déjà pris.', 'danger')
        else:
            hash_password = generate_password_hash(password)
            new_user = User(username=username, email=email, password=hash_password)
            db.session.add(new_user)
            try:
                db.session.commit()
                flash('Inscription réussie ! Connectez-vous.', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                logger.error(f"Erreur lors de l'inscription : {e}")
                flash("Une erreur est survenue. Veuillez réessayer.", "danger")
    return render_template('index.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('Vous êtes déconnecté.', 'info')
    return redirect(url_for('home'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        flash('Veuillez vous connecter pour accéder à votre profil.', 'warning')
        return redirect(url_for('login'))
    username = session.get('username')
    user = User.query.get(session['user_id'])
    if not user:
        flash('Utilisateur introuvable.', 'danger')
        return redirect(url_for('login'))

    profile = user.profile
    if request.method == 'POST':
        complete_name = request.form['complete_name']
        email = request.form['email']
        bio = request.form['bio']
        year_of_study = request.form.get('year_of_study')
        avatar_file = request.files.get('avatar')
        avatar_path = profile.avatar_path if profile else None

        if avatar_file and avatar_file.filename != '':
            if allowed_file(avatar_file.filename):
                upload_result = upload_avatar_to_cloudinary(avatar_file)
                if upload_result:
                    avatar_path = upload_result
                else:
                    return redirect(url_for('profile'))
            else:
                flash('Seules les images (png, jpg, jpeg, gif) sont autorisées.', 'danger')
                return redirect(url_for('profile'))

        if profile:
            profile.complete_name = complete_name
            profile.email = email
            profile.bio = bio
            profile.year_of_study = year_of_study
            profile.avatar_path = avatar_path
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

        try:
            db.session.commit()
            flash('Profil mis à jour avec succès !', 'success')
        except Exception as e:
            db.session.rollback()
            logger.error(f"Erreur lors de la mise à jour du profil : {e}")
            flash("Erreur lors de la sauvegarde.", "danger")

        return redirect(url_for('profile'))

    return render_template('profile.html', username=username ,user=user, profile=profile)

# --------------------
# Démarrage
# --------------------
if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

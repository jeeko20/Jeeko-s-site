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

# --------------------
# Configuration de base
# --------------------
load_dotenv()

# Activer les logs
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# 🔧 Récupérer et corriger DATABASE_URL (postgres:// → postgresql://)
database_url = os.environ.get("DATABASE_URL")
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.environ.get("SECRET_KEY", "fallback_secret_key_change_in_prod")
app.permanent_session_lifetime = timedelta(days=7)

# --------------------
# Initialisation des extensions
# --------------------
db = SQLAlchemy(app)
migrate = Migrate(app, db)  # 👈 IMPORTANT : après db

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
    password = db.Column(db.String(256), nullable=False)  # ✅ Augmenté à 256
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
    """Upload un fichier vers Cloudinary et retourne l'URL publique."""
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

        # Gestion de l'avatar
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

        # Mise à jour du profil
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

    return render_template('profile.html', user=user, profile=profile)


# --------------------
# Route de test (optionnelle)
# --------------------
@app.route('/test-db')
def test_db():
    try:
        db.session.execute('SELECT 1')
        return "<h1>✅ Base de données connectée !</h1>"
    except Exception as e:
        return f"<h1>❌ Erreur DB : {str(e)}</h1>"


# --------------------
# Démarrage (local uniquement)
# --------------------
if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

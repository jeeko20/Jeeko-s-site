import os
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template,session, request, redirect,Response, url_for, flash, jsonify,send_from_directory, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import cloudinary
import cloudinary.uploader
from dotenv import load_dotenv
import PyPDF2
from io import BytesIO
from werkzeug.utils import secure_filename
from cloudinary.utils import cloudinary_url
from sqlalchemy.orm import joinedload
from flask_compress import Compress
import secrets

# ====================

# -------------------- Imports --------------------
import io
import json
import pickle
import tempfile
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from zipfile import ZipFile
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

# -------------------- Config YouTube --------------------
YOUTUBE_SCOPES = ["https://www.googleapis.com/auth/youtube.upload"]

def get_client_config():
    """Renvoie le dict JSON des credentials depuis la variable d'environnement."""
    secrets_json = os.environ.get("YOUTUBE_CLIENT_SECRET")
    if not secrets_json:
        raise RuntimeError("❌ Variable d'environnement YOUTUBE_CLIENT_SECRET manquante !")
    return json.loads(secrets_json)
# -------------------- Configuration --------------------

load_dotenv()
# 🔥 Ajoute cette ligne ici
if os.getenv("RENDER") is None:
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "fallback_secret_key")
app.permanent_session_lifetime = timedelta(days=7)

# -------------------- Compression GZIP --------------------
compress = Compress()
compress.init_app(app)

# -------------------- Database --------------------
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///todo.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
# -------------------- Flask-Login --------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Veuillez vous connecter pour accéder à cette page."
login_manager.login_message_category = "warning"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------------------- Cloudinary --------------------
cloudinary.config(
    cloud_name=os.environ.get("CLOUDINARY_CLOUD_NAME"),
    api_key=os.environ.get("CLOUDINARY_API_KEY"),
    api_secret=os.environ.get("CLOUDINARY_API_SECRET")
)

ALLOWED_EXTENSIONS = {
    'png', 'jpg', 'jpeg', 'gif',     # images
    'pdf', 'doc', 'docx',            # documents
    'mp4', 'mov', 'avi', 'mkv', 'webm'  # vidéos
}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS    

def allow_avatar_file(filename):
     return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png','jpg','jpeg','gif'}


def upload_avatar_to_cloudinary(file):
    try:
        result = cloudinary.uploader.upload(
            file,
            folder="edushare/avatars",
            public_id=f"avatar_{current_user.id}_{int(datetime.utcnow().timestamp())}",
            overwrite=True,
            invalidate=True,
            use_filename=False,
            unique_filename=True,
            access_mode="public",  # 🔥 CRITIQUE
            type="upload"
        )
        secure_url = result.get("secure_url")
        logger.info(f"✅ Avatar uploadé avec permissions publiques: {secure_url}")
        return secure_url
    except Exception as e:
        logger.error(f"❌ Erreur Cloudinary: {e}")
        flash("Échec de l'upload de l'image.", "danger")
        return None

# -------------------- Modèles --------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    profile = db.relationship('Profile', backref='user', uselist=False)
    youtube_credentials = db.Column(db.LargeBinary, nullable=True)
    security_question = db.Column(db.String(200))
    security_answer = db.Column(db.String(200))

    @property
    def avatar_url(self):
        if self.profile and self.profile.avatar_path:
            return fix_cloudinary_url(self.profile.avatar_path)
        return "https://cdn.pixabay.com/photo/2024/06/22/22/55/man-8847064_640.jpg"

class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    complete_name = db.Column(db.String(100))
    email = db.Column(db.String(150))
    bio = db.Column(db.Text)
    year_of_study = db.Column(db.String(50))
    field_of_study = db.Column(db.String(100))
    custom_field = db.Column(db.String(100))
    avatar_path = db.Column(db.String(200))

class Ressource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    subject = db.Column(db.String(50), nullable=False)
    file_url = db.Column(db.String(500), nullable=False)
    download_url = db.Column(db.String(500), nullable=True)
    file_type = db.Column(db.String(20), nullable=False)
    page_count = db.Column(db.Integer, default=0)
    likes = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('ressources', lazy=True))

    @property
    def user_avatar(self):
        return self.user.avatar_url

class Discussion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    subject = db.Column(db.String(50), nullable=False)
    content = db.Column(db.Text, nullable=False)
    likes = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('discussions', lazy=True))

    @property
    def user_avatar(self):
        return self.user.avatar_url

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    discussion_id = db.Column(db.Integer, db.ForeignKey('discussion.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('comments', lazy=True))
    # Relationship to discussion and to parent/children comments (threaded)
    discussion = db.relationship('Discussion', backref=db.backref('comments', lazy=True, cascade="all, delete-orphan"))
    parent = db.relationship('Comment', remote_side=[id], backref=db.backref('children', lazy=True))

    @property
    def user_avatar(self):
        return self.user.avatar_url

class SavedRessource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ressource_id = db.Column(db.Integer, db.ForeignKey('ressource.id'), nullable=False)
    saved_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('saved_ressources', lazy=True))
    ressource = db.relationship('Ressource', backref=db.backref('saved_by', lazy=True))
    __table_args__ = (db.UniqueConstraint('user_id', 'ressource_id', name='unique_user_ressource'),)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ressource_id = db.Column(db.Integer, db.ForeignKey('ressource.id'), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('notifications', lazy=True))
    ressource = db.relationship('Ressource', backref=db.backref('notifications', lazy=True))

# -------------------- Modèles Quiz & Flashcards --------------------
class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    subject = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    time_limit = db.Column(db.Integer, default=0)
    is_public = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('quizzes', lazy=True))
    questions = db.relationship('Question', backref='quiz', cascade="all, delete-orphan")
    attempts = db.relationship('QuizAttempt', backref='quiz', cascade="all, delete-orphan")

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    question_text = db.Column(db.Text, nullable=False)
    question_type = db.Column(db.String(20), default='multiple_choice')
    options = db.Column(db.JSON)  # ← C'est correct
    correct_answer = db.Column(db.String(10), nullable=False)
    explanation = db.Column(db.Text)
    order = db.Column(db.Integer, default=0)
class Flashcard(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    subject = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    is_public = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('flashcards', lazy=True))

class FlashcardItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    flashcard_id = db.Column(db.Integer, db.ForeignKey('flashcard.id'), nullable=False)
    front_content = db.Column(db.Text, nullable=False)
    back_content = db.Column(db.Text, nullable=False)
    order = db.Column(db.Integer, default=0)
    flashcard = db.relationship('Flashcard', backref=db.backref('cards', lazy=True, cascade="all, delete-orphan"))

class QuizAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    score = db.Column(db.Float, default=0)
    total_questions = db.Column(db.Integer, default=0)
    time_taken = db.Column(db.Integer, default=0)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('quiz_attempts', lazy=True))
 
# Dans vos modèles, assurez-vous que QuizNotification peut gérer les deux types
class QuizNotification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=True)
    flashcard_id = db.Column(db.Integer, db.ForeignKey('flashcard.id'), nullable=True)
    message = db.Column(db.String(500), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    notification_type = db.Column(db.String(20), default='quiz')  # 'quiz' ou 'flashcard'
    
    user = db.relationship('User', backref=db.backref('quiz_notifications', lazy=True))
    quiz = db.relationship('Quiz', backref=db.backref('notifications', lazy=True))
    flashcard = db.relationship('Flashcard', backref=db.backref('notifications', lazy=True))

def fix_cloudinary_url(url):
    """Corrige les URLs Cloudinary si nécessaire"""
    if not url:
        return "https://cdn.pixabay.com/photo/2024/06/22/22/55/man-8847064_640.jpg"
    
    if url.startswith('http'):
        return url
    
    if '/' in url and '.' in url:
        clean_public_id = url.replace('edushare/avatars/', '').replace('edushare/ressources/', '')
        return f"https://res.cloudinary.com/ddzx1fktv/image/upload/{clean_public_id}"
    
    return "https://cdn.pixabay.com/photo/2024/06/22/22/55/man-8847064_640.jpg"

# -------------------- Filtre Jinja --------------------
def time_ago(dt):
    now = datetime.utcnow()
    diff = now - dt
    seconds = diff.total_seconds()
    if seconds < 60:
        return "à l'instant"
    elif seconds < 3600:
        return f"il y a {int(seconds // 60)} minute{'s' if int(seconds // 60) > 1 else ''}"
    elif seconds < 86400:
        return f"il y a {int(seconds // 3600)} heure{'s' if int(seconds // 3600) > 1 else ''}"
    elif seconds < 604800:
        return f"il y a {int(seconds // 86400)} jour{'s' if int(seconds // 86400) > 1 else ''}"
    else:
        return dt.strftime("%d/%m/%Y")

app.jinja_env.filters['time_ago'] = time_ago

# -------------------- Before Request --------------------
@app.before_request
def update_last_seen():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()

# -------------------- Routes --------------------
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/api/stats')
def api_stats():
    total_users = User.query.count()
    threshold = datetime.utcnow() - timedelta(minutes=5)
    active_users = User.query.filter(User.last_seen >= threshold).count()
    return jsonify({
        "total_users": total_users,
        "active_users": active_users,
        "total_ressources": Ressource.query.count(),
    })

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and user.is_active and check_password_hash(user.password, password):
            login_user(user, remember=True)
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
        security_question = request.form['security_question']
        security_answer = request.form['security_answer']
        
        if not all([username, email, password, security_question, security_answer]):
            flash('Tous les champs sont obligatoires.', 'danger')
            return render_template('index.html')
            
        if User.query.filter_by(email=email).first():
            flash('Cet email est déjà utilisé.', 'danger')
        elif User.query.filter_by(username=username).first():
            flash('Ce nom d\'utilisateur est déjà pris.', 'danger')
        else:
            hash_password = generate_password_hash(password)
            new_user = User(
                username=username, 
                email=email, 
                password=hash_password,
                security_question=security_question,
                security_answer=security_answer.lower()
            )
            db.session.add(new_user)
            try:
                db.session.commit()
                flash('Inscription réussie, veuillez creer un profile !', 'success')
                user = User.query.filter_by(email=email).first()      
                login_user(user, remember=True)
                return redirect(url_for('profile'))
            except Exception as e:
                db.session.rollback()
                logger.error(f"Erreur lors de l'inscription : {e}")
                flash("Une erreur est survenue. Veuillez réessayer.", "danger")
    return render_template('index.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            return redirect(url_for('security_question', user_id=user.id))
        else:
            flash('Aucun compte trouvé avec cet email.', 'danger')
    
    return render_template('forgot_password.html')

@app.route('/security_question/<int:user_id>', methods=['GET', 'POST'])
def security_question(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        answer = request.form.get('security_answer')
        
        if answer and answer.lower() == user.security_answer.lower():
            token = secrets.token_urlsafe(16)
            session['reset_token'] = token
            session['reset_user_id'] = user.id
            session['reset_expires'] = (datetime.utcnow() + timedelta(hours=1)).timestamp()
            
            return redirect(url_for('reset_password'))
        else:
            flash('Réponse incorrecte.', 'danger')
    
    return render_template('security_question.html', user=user)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    token = session.get('reset_token')
    user_id = session.get('reset_user_id')
    expires = session.get('reset_expires')
    
    if not token or not user_id or datetime.utcnow().timestamp() > expires:
        flash('Lien expiré ou invalide.', 'danger')
        return redirect(url_for('forgot_password'))
    
    user = User.query.get(user_id)
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Les mots de passe ne correspondent pas.', 'danger')
        elif len(password) < 6:
            flash('Le mot de passe doit contenir au moins 6 caractères.', 'danger')
        else:
            user.password = generate_password_hash(password)
            db.session.commit()
            
            session.pop('reset_token', None)
            session.pop('reset_user_id', None)
            session.pop('reset_expires', None)
            
            flash('Votre mot de passe a été réinitialisé avec succès !', 'success')
            login_user(user)
            return redirect(url_for('home'))
    
    return render_template('reset_password.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Vous êtes déconnecté.', 'info')
    return redirect(url_for('home'))

def get_field_display_name(field_value, custom_value=None):
    """Retourne le nom d'affichage de la filière"""
    fields = {
        'informatique': 'Informatique',
        'administration': 'Administration',
        'education': 'Éducation',
        'medecine': 'Médecine',
        'droit': 'Droit',
        'ingenierie': 'Ingénierie',
        'commerce': 'Commerce',
        'autre': custom_value or 'Autre'
    }
    return fields.get(field_value, 'Non spécifiée')

@app.context_processor
def utility_processor():
    return dict(get_field_display_name=get_field_display_name)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        complete_name = request.form['complete_name']
        email = request.form['email']
        bio = request.form['bio']
        year_of_study = request.form.get('year_of_study')
        field_of_study = request.form.get('field_of_study')
        custom_field = request.form.get('custom_field')
        avatar_file = request.files.get('avatar')
        avatar_path = current_user.profile.avatar_path if current_user.profile else None
        
        email_exist = Profile.query.filter(
            Profile.email == email, 
            Profile.user_id != current_user.id
        ).first()
        if email_exist:
            flash('Cet email est déjà pris', 'danger')
            return redirect(url_for('profile'))

        if avatar_file and avatar_file.filename != '':
            if allow_avatar_file(avatar_file.filename):
                upload_result = upload_avatar_to_cloudinary(avatar_file)
                if upload_result:
                    avatar_path = upload_result
                else:
                    return redirect(url_for('profile'))
            else:
                flash('Seules les images (png, jpg, jpeg, gif) sont autorisées.', 'danger')
                return redirect(url_for('profile'))

        if current_user.profile:
            current_user.profile.complete_name = complete_name
            current_user.profile.email = email
            current_user.profile.bio = bio
            current_user.profile.year_of_study = year_of_study
            current_user.profile.field_of_study = field_of_study
            current_user.profile.custom_field = custom_field if field_of_study == 'autre' else None
            current_user.profile.avatar_path = avatar_path
        else:
            new_profile = Profile(
                complete_name=complete_name,
                email=email,
                bio=bio,
                year_of_study=year_of_study,
                field_of_study=field_of_study,
                custom_field=custom_field if field_of_study == 'autre' else None,
                avatar_path=avatar_path,
                user_id=current_user.id
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
    
    return render_template('profile.html', user=current_user, profile=current_user.profile)

@app.route('/communaute')
@login_required
def communaute():
    if not current_user.profile or not current_user.profile.year_of_study or not current_user.profile.field_of_study:
        flash("Veuillez compléter votre profil (notamment votre année d'étude et votre filière) pour accéder à la communauté.", "info")
        return redirect(url_for('profile'))
    return render_template('communaute.html')

@app.route('/videos')
@login_required
def videos():
    if not current_user.profile or not current_user.profile.year_of_study or not current_user.profile.field_of_study:
        flash("Veuillez compléter votre profil (notamment votre année d'étude et votre filière) pour accéder aux vidéos.", "info")
        return redirect(url_for('profile'))
    return render_template('videos.html')

MAX_FILE_SIZE = 50 * 1024 * 1024

@app.route('/share_ressource', methods=['POST'])
@login_required
def share_ressource():
    try:
        if not current_user.profile or not current_user.profile.year_of_study or not current_user.profile.field_of_study:
            flash("Veuillez compléter votre profil avant de partager une ressource.", "warning")
            return redirect(url_for('profile'))

        title = request.form.get('titre')
        subject = request.form.get('matiere')
        files = request.files.getlist('files')
        if not title or not subject or not files:
            flash('Tous les champs sont obligatoires.', 'danger')
            return redirect(url_for('communaute'))

        valid_files = [f for f in files if f and f.filename != '']
        if not valid_files:
            flash('Aucun fichier valide sélectionné.', 'danger')
            return redirect(url_for('communaute'))

        uploaded_count = 0
        new_ressources = []

        for file in valid_files:
            filename = secure_filename(file.filename)
            if '.' not in filename:
                flash(f'Fichier invalide (pas d\'extension) : {filename}', 'warning')
                continue
            ext = filename.rsplit('.', 1)[1].lower()
            if ext not in ALLOWED_EXTENSIONS:
                flash(f'Type de fichier non autorisé : {ext} (fichier : {filename})', 'danger')
                continue

            try:
                file.seek(0, os.SEEK_END)
                file_size = file.tell()
                file.seek(0)
                if file_size > MAX_FILE_SIZE:
                    flash(f"Fichier trop volumineux (max 50 Mo) : {filename}", "danger")
                    continue
            except Exception as e:
                logger.error(f"Erreur taille fichier {filename}: {e}")
                flash(f"Erreur avec le fichier : {filename}", "danger")
                continue

            is_video = ext in {'mp4', 'mov', 'avi', 'mkv', 'webm'}
            is_document = ext in {'pdf', 'doc', 'docx'}
            resource_type = 'video' if is_video else ('raw' if is_document else 'image')

            page_count = 0
            if ext == 'pdf':
                try:
                    file.stream.seek(0)
                    pdf_reader = PyPDF2.PdfReader(file.stream)
                    page_count = len(pdf_reader.pages)
                except Exception as e:
                    logger.warning(f"Impossible de lire le PDF {filename}: {e}")
                    page_count = 0
                finally:
                    file.stream.seek(0)

            try:
                upload_result = cloudinary.uploader.upload(
                    file,
                    resource_type=resource_type,
                    folder="edushare/ressources",
                    public_id=filename,
                    overwrite=True,
                    invalidate=True,
                    use_filename=False,
                    unique_filename=True,
                    access_mode="public",
                    type="upload"
                )

                if resource_type == "image":
                    file_url = upload_result.get("secure_url")
                    download_url, _ = cloudinary_url(
                        upload_result.get("public_id"),
                        resource_type="image",
                        flags="attachment",
                        secure=True
                    )
                elif resource_type == "video":
                    file_url = upload_result.get("secure_url")
                    download_url = file_url
                else:
                    file_url, _ = cloudinary_url(
                        upload_result.get("public_id"),
                        resource_type="raw",
                        secure=True
                    )
                    download_url, _ = cloudinary_url(
                        upload_result.get("public_id"),
                        resource_type="raw",
                        flags="attachment",
                        secure=True
                    )
            except Exception as e:
                logger.error(f"Erreur Cloudinary pour {filename}: {e}")
                flash(f"Échec de l'upload : {filename}", "danger")
                continue

            new_ressource = Ressource(
                user_id=current_user.id,
                title=title,
                subject=subject,
                file_url=file_url,
                download_url=download_url,
                file_type=ext,
                page_count=page_count
            )
            db.session.add(new_ressource)
            uploaded_count += 1

        db.session.commit()
        
        if uploaded_count > 0 and current_user.profile and current_user.profile.year_of_study and current_user.profile.field_of_study:
            new_ressources = Ressource.query.filter_by(
                user_id=current_user.id, 
                title=title, 
                subject=subject
            ).order_by(Ressource.created_at.desc()).limit(uploaded_count).all()
            
            users_same_year_and_field = User.query.join(Profile).filter(
                Profile.year_of_study == current_user.profile.year_of_study,
                Profile.field_of_study == current_user.profile.field_of_study,
                User.is_active == True
            ).all()
            
            logger.info(f"📢 Création de notifications pour {len(users_same_year_and_field)} utilisateurs")
            
            for new_ressource in new_ressources:
                resource_type_label = "vidéo" if new_ressource.file_type in ['mp4', 'mov', 'avi', 'mkv', 'webm'] else "ressource"
                
                for user in users_same_year_and_field:
                    if user.id == current_user.id:
                        message = f"Vous avez partagé une nouvelle {resource_type_label} : {new_ressource.title}"
                    else:
                        message = f"{current_user.username} a partagé une nouvelle {resource_type_label} : {new_ressource.title}"
                    
                    notification = Notification(
                        user_id=user.id,
                        ressource_id=new_ressource.id,
                        message=message
                    )
                    db.session.add(notification)
            
            db.session.commit()
            logger.info(f"✅ {len(users_same_year_and_field) * len(new_ressources)} notifications créées avec succès")
        
        if uploaded_count > 0:
            flash(f'✅ {uploaded_count} ressource(s) partagée(s) avec succès !', 'success')
        else:
            flash('Aucune ressource n\'a pu être partagée.', 'warning')
            
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erreur lors du partage de ressource : {e}")
        if "users_same_year" in str(e):
            flash("Les fichiers ont été uploadés mais erreur lors de la création des notifications.", "warning")
        else:
            flash("Erreur lors de la publication. Veuillez réessayer.", "danger")
        
    return redirect(url_for('communaute'))

@app.route('/debug/user_notifications')
@login_required
def debug_user_notifications():
    notifications = Notification.query.filter_by(user_id=current_user.id)\
        .options(joinedload(Notification.ressource))\
        .order_by(Notification.created_at.desc())\
        .all()
    
    debug_info = {
        "current_user_id": current_user.id,
        "current_user_username": current_user.username,
        "notifications_count": len(notifications),
        "notifications": [{
            "id": n.id,
            "message": n.message,
            "is_read": n.is_read,
            "ressource_id": n.ressource_id,
            "ressource_type": n.ressource.file_type if n.ressource else None,
            "created_at": n.created_at.strftime("%Y-%m-%dT%H:%M:%SZ")
        } for n in notifications]
    }
    
    return jsonify(debug_info)

@app.route('/debug/cloudinary_config')
def debug_cloudinary_config():
    try:
        test_result = cloudinary.uploader.upload(
            "https://cdn.pixabay.com/photo/2024/06/22/22/55/man-8847064_640.jpg",
            public_id="test_config",
            folder="edushare/test",
            access_mode="public",
            overwrite=True
        )
        
        return jsonify({
            "status": "success", 
            "test_url": test_result.get("secure_url"),
            "cloud_name": os.environ.get("CLOUDINARY_CLOUD_NAME"),
            "api_key_set": bool(os.environ.get("CLOUDINARY_API_KEY")),
            "api_secret_set": bool(os.environ.get("CLOUDINARY_API_SECRET"))
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "error": str(e),
            "cloud_name": os.environ.get("CLOUDINARY_CLOUD_NAME"),
            "api_key_set": bool(os.environ.get("CLOUDINARY_API_KEY")),
            "api_secret_set": bool(os.environ.get("CLOUDINARY_API_SECRET"))
        })

# Route pour les statistiques des notes
@app.route('/api/notes/stats')
@login_required
def api_notes_stats():
    try:
        # Nombre total de ressources partagées par l'utilisateur
        total_shared = Ressource.query.filter_by(user_id=current_user.id).count()
        
        # Nombre de ressources sauvegardées par l'utilisateur
        total_saved = SavedRessource.query.filter_by(user_id=current_user.id).count()
        
        # Nombre total de ressources (partagées + sauvegardées)
        total_notes = total_shared + total_saved
        
        # Nombre de matières distinctes dans les ressources partagées
        shared_subjects = db.session.query(Ressource.subject)\
            .filter_by(user_id=current_user.id)\
            .distinct()\
            .count()
        
        # Nombre de matières distinctes dans les ressources sauvegardées
        saved_subjects = db.session.query(Ressource.subject)\
            .join(SavedRessource)\
            .filter(SavedRessource.user_id == current_user.id)\
            .distinct()\
            .count()
        
        # Total des matières uniques (en combinant partagées et sauvegardées)
        all_subjects_shared = db.session.query(Ressource.subject)\
            .filter_by(user_id=current_user.id)\
            .distinct()\
            .all()
        
        all_subjects_saved = db.session.query(Ressource.subject)\
            .join(SavedRessource)\
            .filter(SavedRessource.user_id == current_user.id)\
            .distinct()\
            .all()
        
        # Combiner et compter les matières uniques
        all_subjects = set([subject[0] for subject in all_subjects_shared] + 
                          [subject[0] for subject in all_subjects_saved])
        total_subjects = len(all_subjects)
        
        return jsonify({
            "success": True,
            "stats": {
                "total_notes": total_notes,
                "total_shared": total_shared,
                "total_saved": total_saved,
                "total_subjects": total_subjects
            }
        })
        
    except Exception as e:
        logger.error(f"Erreur lors du calcul des stats notes: {e}")
        return jsonify({
            "success": False,
            "error": str(e),
            "stats": {
                "total_notes": 0,
                "total_shared": 0,
                "total_saved": 0,
                "total_subjects": 0
            }
        }), 500

# Route pour obtenir les ressources de l'utilisateur (pour le détail)
@app.route('/api/my_notes')
@login_required
def api_my_notes():
    try:
        # Récupérer les ressources partagées par l'utilisateur
        shared_ressources = Ressource.query.filter_by(user_id=current_user.id)\
            .options(joinedload(Ressource.user))\
            .order_by(Ressource.created_at.desc())\
            .all()
        
        # Récupérer les ressources sauvegardées par l'utilisateur
        saved_ressources = SavedRessource.query.filter_by(user_id=current_user.id)\
            .options(joinedload(SavedRessource.ressource).joinedload(Ressource.user))\
            .order_by(SavedRessource.saved_at.desc())\
            .all()
        
        # Transformer les données
        shared_data = [{
            "id": r.id,
            "title": r.title,
            "subject": r.subject,
            "file_type": r.file_type,
            "file_url": r.file_url,
            "download_url": r.download_url,
            "created_at": r.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "page_count": r.page_count,
            "is_saved": True,  # C'est une ressource partagée par l'utilisateur
            "is_shared": True,
            "type": "shared"
        } for r in shared_ressources]
        
        saved_data = [{
            "id": s.ressource.id,
            "title": s.ressource.title,
            "subject": s.ressource.subject,
            "file_type": s.ressource.file_type,
            "file_url": s.ressource.file_url,
            "download_url": s.ressource.download_url,
            "created_at": s.ressource.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "page_count": s.ressource.page_count,
            "is_saved": True,
            "is_shared": False,
            "saved_at": s.saved_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "type": "saved"
        } for s in saved_ressources]
        
        # Combiner et trier par date
        all_notes = shared_data + saved_data
        all_notes.sort(key=lambda x: x['created_at'], reverse=True)
        
        return jsonify({
            "success": True,
            "notes": all_notes,
            "count": len(all_notes)
        })
        
    except Exception as e:
        logger.error(f"Erreur lors du chargement des notes: {e}")
        return jsonify({
            "success": False,
            "error": str(e),
            "notes": [],
            "count": 0
        }), 500

@app.route('/api/ressources')
@login_required
def api_ressources():
    if not current_user.profile or not current_user.profile.year_of_study or not current_user.profile.field_of_study:
        return jsonify([])
    current_year = current_user.profile.year_of_study
    current_field = current_user.profile.field_of_study

    ressources = Ressource.query.join(User).join(Profile).filter(
        Profile.year_of_study == current_year,
        Profile.field_of_study == current_field
    ).options(joinedload(Ressource.user)).all()

    saved_ids = {sr.ressource_id for sr in SavedRessource.query.filter_by(user_id=current_user.id).all()}

    return jsonify([{
        "id": r.id,
        "user_id": r.user_id,
        "title": r.title,
        "subject": r.subject,
        "file_type": r.file_type,
        "likes": r.likes,
    "created_at": r.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "user_avatar": r.user.avatar_url,
        "username": r.user.username,
        "file_url": r.file_url,
        "download_url": r.download_url,
        "is_saved": r.id in saved_ids,
        "is_video": r.file_type in ['mp4', 'mov', 'avi', 'mkv', 'webm','youtube'],
        "page_count": r.page_count
    } for r in ressources])

@app.route('/api/videos')
@login_required
def api_videos():
    if not current_user.profile or not current_user.profile.year_of_study or not current_user.profile.field_of_study:
        return jsonify([])
    
    current_year = current_user.profile.year_of_study
    current_field = current_user.profile.field_of_study

    video_types = ['mp4', 'mov', 'avi', 'mkv', 'webm','youtube']
    videos = Ressource.query.join(User).join(Profile).filter(
        Profile.year_of_study == current_year,
        Profile.field_of_study == current_field,
        Ressource.file_type.in_(video_types)
    ).options(joinedload(Ressource.user)).order_by(Ressource.created_at.desc()).all()

    saved_ids = {sr.ressource_id for sr in SavedRessource.query.filter_by(user_id=current_user.id).all()}
    return jsonify([{
        "id": r.id,
        "title": r.title,
        "subject": r.subject,
        "file_type": r.file_type,
        "likes": r.likes,
    "created_at": r.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "user_avatar": r.user.avatar_url,
        "username": r.user.username,
        "file_url": r.file_url,
        "download_url": r.download_url,
        "is_saved": r.id in saved_ids
    } for r in videos])

@app.route('/api/discussions', methods=['GET'])
@login_required
def api_discussions():
    if not current_user.profile or not current_user.profile.year_of_study or not current_user.profile.field_of_study:
        return jsonify([])
    current_year = current_user.profile.year_of_study
    current_field = current_user.profile.field_of_study
    query = Discussion.query.join(User).join(Profile).filter(
        Profile.year_of_study == current_year,
        Profile.field_of_study == current_field
    ).options(
        joinedload(Discussion.user),
        joinedload(Discussion.comments)
    )

    sort_by = request.args.get('sort', 'date')
    if sort_by == 'likes':
        query = query.order_by(Discussion.likes.desc())
    elif sort_by == 'subject':
        query = query.order_by(Discussion.subject)
    else:
        query = query.order_by(Discussion.created_at.desc())

    discussions = query.all()
    return jsonify([{
        "id": d.id,
        "user_id": d.user_id,
        "title": d.title,
        "subject": d.subject,
        "content": d.content,
        "likes": d.likes,
    "created_at": d.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "user_avatar": d.user.avatar_url,
        "username": d.user.username,
        "comment_count": len(d.comments)
    } for d in discussions])

@app.route('/api/discussion', methods=['POST'])
@login_required
def create_discussion():
    if not current_user.profile or not current_user.profile.year_of_study or not current_user.profile.field_of_study:
        return jsonify({"error": "Veuillez compléter votre profil (année d'étude ET filière) avant de créer une discussion."}), 403

    data = request.get_json()
    title = data.get('title')
    subject = data.get('subject')
    content = data.get('content')
    if not title or not subject or not content:
        return jsonify({"error": "Tous les champs sont requis"}), 400

    new_discussion = Discussion(
        user_id=current_user.id,
        title=title,
        subject=subject,
        content=content
    )
    db.session.add(new_discussion)
    db.session.commit()
    return jsonify({
        "id": new_discussion.id,
        "title": new_discussion.title,
        "subject": new_discussion.subject,
        "content": new_discussion.content,
        "likes": 0,
    "created_at": new_discussion.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "user_avatar": new_discussion.user.avatar_url,
        "username": new_discussion.user.username,
        "comment_count": 0
    }), 201


@app.route('/api/discussion/<int:discussion_id>', methods=['DELETE'])
@login_required
def delete_discussion(discussion_id):
    """Supprime une discussion (seul l'auteur peut supprimer)."""
    discussion = Discussion.query.get(discussion_id)
    if not discussion:
        return jsonify({"error": "Discussion introuvable."}), 404

    if discussion.user_id != current_user.id:
        return jsonify({"error": "Vous n'êtes pas autorisé·e à supprimer cette discussion."}), 403

    try:
        db.session.delete(discussion)
        db.session.commit()
        return jsonify({"success": True}), 200
    except Exception as e:
        db.session.rollback()
        logger.exception(e)
        return jsonify({"success": False, "error": "Erreur lors de la suppression."}), 500


@app.route('/api/ressources/download', methods=['POST'])
@login_required
def api_ressources_download():
    """Proxy côté serveur pour télécharger une ou plusieurs URLs et renvoyer
    soit le fichier unique (stream) soit un ZIP contenant plusieurs fichiers.

    Corps JSON attendu: { "files": [url1, url2, ...], "title": "nom" }
    """
    data = request.get_json() or {}
    files = data.get('files') or []
    title = data.get('title') or 'resources'
    if not files:
        return jsonify({"error": "Aucune URL fournie."}), 400

    logger.info('API download request received. files=%s title=%s user_id=%s', files, title, getattr(current_user, 'id', None))

    # Préparer une session requests avec retries pour plus de robustesse
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    # Si un seul fichier : proxy stream direct
    if len(files) == 1:
        url = files[0]
        try:
            r = session.get(url, stream=True, timeout=30,
                            headers={'User-Agent': 'Mozilla/5.0 (compatible; EduShare/1.0)'},
                            allow_redirects=True)
        except Exception as e:
            logger.exception('Erreur fetch remote file for URL: %s', url)
            return jsonify({"error": "Impossible de récupérer le fichier distant.", "detail": str(e)}), 502

        if r.status_code != 200:
            logger.warning('Remote file returned status %s for URL: %s', r.status_code, url)
            return jsonify({"error": f"Fichier distant introuvable (status {r.status_code}).", "status": r.status_code}), 502

        # Déterminer un nom de fichier
        filename = secure_filename(url.split('?')[0].split('/')[-1]) or f"file_{int(datetime.utcnow().timestamp())}"
        response = Response(r.iter_content(chunk_size=4096), content_type=r.headers.get('Content-Type', 'application/octet-stream'))
        response.headers.set('Content-Disposition', f'attachment; filename="{filename}"')
        return response

    # Plusieurs fichiers -> créer ZIP en mémoire
    try:
        zip_io = io.BytesIO()
        with ZipFile(zip_io, 'w') as zf:
            for idx, url in enumerate(files, start=1):
                try:
                    # idem pour les requêtes multiples : utiliser la session avec retries
                    rr = session.get(url, timeout=30,
                                     headers={'User-Agent': 'Mozilla/5.0 (compatible; EduShare/1.0)'},
                                     allow_redirects=True)
                    if rr.status_code != 200:
                        logger.warning('Skip file %s status %s', url, rr.status_code)
                        continue
                    fname = secure_filename(url.split('?')[0].split('/')[-1]) or f"file_{idx}"
                    zf.writestr(f"{str(idx).zfill(2)}_{fname}", rr.content)
                except Exception:
                    logger.exception('Erreur lors de la récupération d\'un fichier pour le ZIP')
                    continue

        zip_io.seek(0)
        zip_name = secure_filename(f"{title}.zip")
        return send_file(zip_io, mimetype='application/zip', as_attachment=True, download_name=zip_name)
    except Exception as e:
        logger.exception('Erreur création ZIP')
        return jsonify({"error": "Erreur lors de la création du ZIP."}), 500




@app.route('/api/save_ressource/<int:ressource_id>', methods=['POST'])
@login_required
def save_ressource(ressource_id):
    ressource = Ressource.query.get_or_404(ressource_id)
    existing = SavedRessource.query.filter_by(user_id=current_user.id, ressource_id=ressource_id).first()
    if not existing:
        saved = SavedRessource(user_id=current_user.id, ressource_id=ressource_id)
        db.session.add(saved)
        db.session.commit()
        return jsonify({"saved": True}), 201
    return jsonify({"saved": True}), 200

@app.route('/api/unsave_ressource/<int:ressource_id>', methods=['POST'])
@login_required
def unsave_ressource(ressource_id):
    saved = SavedRessource.query.filter_by(user_id=current_user.id, ressource_id=ressource_id).first()
    if saved:
        db.session.delete(saved)
        db.session.commit()
        return jsonify({"saved": False}), 200
    return jsonify({"saved": False}), 404

@app.route('/api/saved_ressources')
@login_required
def api_saved_ressources():
    saved = SavedRessource.query.options(
        joinedload(SavedRessource.ressource).joinedload(Ressource.user)
    ).filter_by(user_id=current_user.id).all()
    return jsonify([{
        "id": s.ressource.id,
        "title": s.ressource.title,
        "subject": s.ressource.subject,
        "file_type": s.ressource.file_type,
    "created_at": s.ressource.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "file_url": s.ressource.file_url,
        "download_url": s.ressource.download_url,
        "page_count": s.ressource.page_count,
        "user_avatar": s.ressource.user.avatar_url,
        "username": s.ressource.user.username,
        "is_video": s.ressource.file_type in ['mp4', 'mov', 'avi', 'mkv', 'webm']
    } for s in saved])

@app.route('/api/my_ressources')
@login_required
def api_my_ressources():
    ressources = Ressource.query.options(
        joinedload(Ressource.user)
    ).filter_by(user_id=current_user.id).order_by(Ressource.created_at.desc()).all()
    return jsonify([{
        "id": r.id,
        "title": r.title,
        "subject": r.subject,
        "file_type": r.file_type,
    "created_at": r.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "file_url": r.file_url,
        "download_url": r.download_url,
        "page_count": r.page_count,
        "is_video": r.file_type in ['mp4', 'mov', 'avi', 'mkv', 'webm']
    } for r in ressources])

@app.route('/api/discussion/<int:discussion_id>/comments', methods=['GET'])
def get_comments(discussion_id):
    comments = Comment.query.options(
        joinedload(Comment.user),
        joinedload(Comment.children)
    ).filter_by(discussion_id=discussion_id).order_by(Comment.created_at.asc()).all()

    def serialize_comment(c):
        return {
            "id": c.id,
            "content": c.content,
            "created_at": c.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "user_avatar": c.user.avatar_url,
            "user_id": c.user_id,
            "username": c.user.username,
            "parent_id": c.parent_id,
            "children": [serialize_comment(child) for child in sorted(c.children, key=lambda x: x.created_at)]
        }

    # Return only top-level comments; children nested inside
    top_level = [c for c in comments if c.parent_id is None]
    return jsonify([serialize_comment(c) for c in sorted(top_level, key=lambda x: x.created_at)])

@app.route('/api/discussion/<int:discussion_id>/comment', methods=['POST'])
@login_required
def add_comment(discussion_id):
    data = request.get_json()
    content = data.get('content')
    parent_id = data.get('parent_id')
    if not content:
        return jsonify({"error": "Contenu requis"}), 400
    new_comment = Comment(
        discussion_id=discussion_id,
        user_id=current_user.id,
        content=content,
        parent_id=parent_id
    )
    db.session.add(new_comment)
    db.session.commit()
    return jsonify({
        "id": new_comment.id,
        "content": new_comment.content,
    "created_at": new_comment.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "user_avatar": new_comment.user.avatar_url,
        "username": new_comment.user.username
    }), 201

@app.route('/api/discussion/<int:discussion_id>/like', methods=['POST'])
@login_required
def like_discussion(discussion_id):
    discussion = Discussion.query.get_or_404(discussion_id)
    discussion.likes += 1
    db.session.commit()
    return jsonify({"likes": discussion.likes}), 200

@app.route('/like_ressource/<int:ressource_id>', methods=['POST'])
@login_required
def like_ressource(ressource_id):
    ressource = Ressource.query.get_or_404(ressource_id)
    ressource.likes += 1
    db.session.commit()
    return jsonify({"likes": ressource.likes}), 200

@app.route('/api/notifications')
@login_required
def api_notifications():
    notifications = Notification.query.filter_by(user_id=current_user.id)\
        .options(joinedload(Notification.ressource))\
        .order_by(Notification.created_at.desc())\
        .limit(50)\
        .all()
    
    return jsonify([{
        "id": n.id,
        "message": n.message,
        "is_read": n.is_read,
        "created_at": n.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ressource_id": n.ressource_id,
        "ressource_type": n.ressource.file_type if n.ressource else None,
        "ressource_title": n.ressource.title if n.ressource else None
    } for n in notifications])

@app.route('/api/notifications/read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    notification = Notification.query.filter_by(id=notification_id, user_id=current_user.id).first()
    if notification:
        notification.is_read = True
        db.session.commit()
        return jsonify({"success": True})
    return jsonify({"error": "Notification non trouvée"}), 404

@app.route('/api/notifications/read_all', methods=['POST'])
@login_required
def mark_all_notifications_read():
    Notification.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True})
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/notifications/count')
@login_required
def unread_notifications_count():
    count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    return jsonify({"count": count})

@app.route('/notes')
@login_required
def notes():
    return render_template('note.html')

@app.route('/learn_html')
def learn_html():
    return render_template('learn_html.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        subject = request.form.get('subject')
        message = request.form.get('message')
        
        whatsapp_message = f"*Nouveau message de contact:*%0A%0A" \
                          f"*Nom:* {name}%0A" \
                          f"*Email:* {email}%0A" \
                          f"*Sujet:* {subject}%0A" \
                          f"*Message:*%0A{message}"
        
        whatsapp_number = "50933970083"
        
        whatsapp_url = f"https://wa.me/{whatsapp_number}?text={whatsapp_message}"
        
        return redirect(whatsapp_url)
    
    return render_template('contact.html')

@app.route('/learn_css')
def learn_css():
    return render_template('learn_css.html')

@app.route('/page_not_found')
def page_not_found():
    return render_template('page_not_found.html')

@app.route('/systeme')
def systeme():
    return render_template('systeme.html')

@app.route('/robots.txt')
def robots():
    return app.send_static_file('robots.txt')

public_routes = [
    "home",
    "about",
    "communaute",
    "learn_html",
    "learn_css",
    "contact",
    "systeme"
]

@app.route("/sitemap.xml", methods=['GET'])
def sitemap():
    sitemap_xml = ['<?xml version="1.0" encoding="UTF-8"?>']
    sitemap_xml.append('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">')

    for route in public_routes:
        url = url_for(route, _external=True)
        sitemap_xml.append(f"""
        <url>
            <loc>{url}</loc>
            <lastmod>{datetime.utcnow().date()}</lastmod>
            <changefreq>weekly</changefreq>
            <priority>0.8</priority>
        </url>
        """)

    sitemap_xml.append('</urlset>')
    sitemap_content = "\n".join(sitemap_xml)
    return Response(sitemap_content, mimetype='application/xml')

# -------------------- Routes Quiz & Flashcards --------------------

@app.route('/quiz_flashcards')
@login_required
def quiz_flashcards():
    if not current_user.profile or not current_user.profile.year_of_study or not current_user.profile.field_of_study:
        flash("Veuillez compléter votre profil pour accéder aux quiz et flashcards.", "info")
        return redirect(url_for('profile'))
    return render_template('quiz_flashcards.html')

# API pour les quiz
@app.route('/api/quizzes')
@login_required
def api_quizzes():
    if not current_user.profile:
        return jsonify([])
    
    current_year = current_user.profile.year_of_study
    current_field = current_user.profile.field_of_study

    quizzes = Quiz.query.join(User).join(Profile).filter(
        Profile.year_of_study == current_year,
        Profile.field_of_study == current_field,
        Quiz.is_public == True
    ).options(joinedload(Quiz.user)).order_by(Quiz.created_at.desc()).all()

    return jsonify([{
        "id": q.id,
        "title": q.title,
        "subject": q.subject,
        "description": q.description,
        "time_limit": q.time_limit,
        "question_count": len(q.questions),
    "created_at": q.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "user_avatar": q.user.avatar_url,
        "username": q.user.username,
        "attempt_count": len(q.attempts)
    } for q in quizzes])

@app.route('/api/my_quizzes')
@login_required
def api_my_quizzes():
    quizzes = Quiz.query.filter_by(user_id=current_user.id)\
        .options(joinedload(Quiz.user))\
        .order_by(Quiz.created_at.desc()).all()

    return jsonify([{
        "id": q.id,
        "title": q.title,
        "subject": q.subject,
        "description": q.description,
        "time_limit": q.time_limit,
        "question_count": len(q.questions),
    "created_at": q.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "user_avatar": q.user.avatar_url,
        "username": q.user.username,
        "attempt_count": len(q.attempts)
    } for q in quizzes])

@app.route('/api/my_flashcards')
@login_required
def api_my_flashcards():
    flashcards = Flashcard.query.filter_by(user_id=current_user.id)\
        .options(joinedload(Flashcard.user))\
        .order_by(Flashcard.created_at.desc()).all()

    return jsonify([{
        "id": f.id,
        "title": f.title,
        "subject": f.subject,
        "description": f.description,
        "card_count": len(f.cards),
    "created_at": f.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "user_avatar": f.user.avatar_url,
        "username": f.user.username
    } for f in flashcards])

# API pour les flashcards
@app.route('/api/flashcards')
@login_required
def api_flashcards():
    if not current_user.profile:
        return jsonify([])
    
    current_year = current_user.profile.year_of_study
    current_field = current_user.profile.field_of_study

    flashcards = Flashcard.query.join(User).join(Profile).filter(
        Profile.year_of_study == current_year,
        Profile.field_of_study == current_field,
        Flashcard.is_public == True
    ).options(joinedload(Flashcard.user)).order_by(Flashcard.created_at.desc()).all()

    return jsonify([{
        "id": f.id,
        "title": f.title,
        "subject": f.subject,
        "description": f.description,
        "card_count": len(f.cards),
    "created_at": f.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "user_avatar": f.user.avatar_url,
        "username": f.user.username
    } for f in flashcards])

# Ajoutez ces routes dans votre fichier Python existant

# Route pour obtenir les participants d'un quiz
@app.route('/api/quiz/<int:quiz_id>/participants')
@login_required
def get_quiz_participants(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    
    # Vérifier que l'utilisateur est le créateur du quiz
    if quiz.user_id != current_user.id:
        return jsonify({"error": "Non autorisé"}), 403
    
    attempts = QuizAttempt.query.filter_by(quiz_id=quiz_id)\
        .options(joinedload(QuizAttempt.user))\
        .order_by(QuizAttempt.score.desc())\
        .all()
    
    return jsonify([{
        "user_id": attempt.user.id,
        "username": attempt.user.username,
        "user_avatar": attempt.user.avatar_url,
        "score": attempt.score,
        "time_taken": attempt.time_taken,
            "completed_at": attempt.completed_at.strftime("%Y-%m-%dT%H:%M:%SZ")
    } for attempt in attempts])
# Route avec recherche et tri


@app.route('/api/quizzes/search')
@login_required
def api_quizzes_search():
    if not current_user.profile:
        return jsonify([])
    
    current_year = current_user.profile.year_of_study
    current_field = current_user.profile.field_of_study
    
    search = request.args.get('search', '')
    sort = request.args.get('sort', 'recent')
    subject = request.args.get('subject', '')
    
    query = Quiz.query.join(User).join(Profile).filter(
        Profile.year_of_study == current_year,
        Profile.field_of_study == current_field,
        Quiz.is_public == True
    ).options(joinedload(Quiz.user))
    
    if search:
        query = query.filter(
            db.or_(
                Quiz.title.ilike(f'%{search}%'),
                Quiz.description.ilike(f'%{search}%'),
                Quiz.subject.ilike(f'%{search}%')
            )
        )
    
    if subject:
        query = query.filter(Quiz.subject == subject)
    
    if sort == 'recent':
        query = query.order_by(Quiz.created_at.desc())
    elif sort == 'oldest':
        query = query.order_by(Quiz.created_at.asc())
    elif sort == 'title_asc':
        query = query.order_by(Quiz.title.asc())
    elif sort == 'title_desc':
        query = query.order_by(Quiz.title.desc())
    
    quizzes = query.all()
    
    return jsonify([{
        "id": q.id,
        "title": q.title,
        "subject": q.subject,
        "description": q.description,
        "time_limit": q.time_limit,
        "question_count": len(q.questions),
    "created_at": q.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "user_avatar": q.user.avatar_url,
        "username": q.user.username,
        "attempt_count": len(q.attempts)
    } for q in quizzes])

@app.route('/api/flashcards/search')
@login_required
def api_flashcards_search():
    if not current_user.profile:
        return jsonify([])
    
    current_year = current_user.profile.year_of_study
    current_field = current_user.profile.field_of_study
    
    search = request.args.get('search', '')
    sort = request.args.get('sort', 'recent')
    subject = request.args.get('subject', '')
    
    query = Flashcard.query.join(User).join(Profile).filter(
        Profile.year_of_study == current_year,
        Profile.field_of_study == current_field,
        Flashcard.is_public == True
    ).options(joinedload(Flashcard.user))
    
    if search:
        query = query.filter(
            db.or_(
                Flashcard.title.ilike(f'%{search}%'),
                Flashcard.description.ilike(f'%{search}%'),
                Flashcard.subject.ilike(f'%{search}%')
            )
        )
    
    if subject:
        query = query.filter(Flashcard.subject == subject)
    
    if sort == 'recent':
        query = query.order_by(Flashcard.created_at.desc())
    elif sort == 'oldest':
        query = query.order_by(Flashcard.created_at.asc())
    elif sort == 'title_asc':
        query = query.order_by(Flashcard.title.asc())
    elif sort == 'title_desc':
        query = query.order_by(Flashcard.title.desc())
    
    flashcards = query.all()
    
    return jsonify([{
        "id": f.id,
        "title": f.title,
        "subject": f.subject,
        "description": f.description,
        "card_count": len(f.cards),
    "created_at": f.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "user_avatar": f.user.avatar_url,
        "username": f.user.username
    } for f in flashcards])

# Route pour les statistiques des participants aux quiz
@app.route('/api/quiz_participants/stats')
@login_required
def api_quiz_participants_stats():
    try:
        # Récupérer tous les quiz créés par l'utilisateur
        user_quizzes = Quiz.query.filter_by(user_id=current_user.id).all()
        
        total_stats = {
            "total_quizzes": len(user_quizzes),
            "total_participants": 0,
            "total_attempts": 0,
            "average_score": 0,
            "best_score": 0,
            "quizzes_with_participants": 0
        }
        
        quiz_details = []
        
        for quiz in user_quizzes:
            # Récupérer les tentatives pour ce quiz
            attempts = QuizAttempt.query.filter_by(quiz_id=quiz.id).all()
            
            if attempts:
                total_stats["quizzes_with_participants"] += 1
                total_stats["total_attempts"] += len(attempts)
                total_stats["total_participants"] += len(set([attempt.user_id for attempt in attempts]))
                
                quiz_scores = [attempt.score for attempt in attempts]
                quiz_avg_score = sum(quiz_scores) / len(quiz_scores)
                quiz_best_score = max(quiz_scores)
                
                total_stats["best_score"] = max(total_stats["best_score"], quiz_best_score)
                
                # Détails par quiz
                quiz_details.append({
                    "quiz_id": quiz.id,
                    "quiz_title": quiz.title,
                    "participant_count": len(set([attempt.user_id for attempt in attempts])),
                    "attempt_count": len(attempts),
                    "average_score": round(quiz_avg_score, 1),
                    "best_score": round(quiz_best_score, 1),
                    "total_questions": len(quiz.questions)
                })
        
        # Calculer la moyenne générale
        if total_stats["total_attempts"] > 0:
            all_scores = []
            for quiz in user_quizzes:
                attempts = QuizAttempt.query.filter_by(quiz_id=quiz.id).all()
                all_scores.extend([attempt.score for attempt in attempts])
            
            total_stats["average_score"] = round(sum(all_scores) / len(all_scores), 1)
        
        # Trier les quiz par nombre de participants (décroissant)
        quiz_details.sort(key=lambda x: x["participant_count"], reverse=True)
        
        return jsonify({
            "success": True,
            "total_stats": total_stats,
            "quiz_details": quiz_details
        })
        
    except Exception as e:
        logger.error(f"Erreur lors du calcul des stats participants: {e}")
        return jsonify({
            "success": False,
            "error": str(e),
            "total_stats": {
                "total_quizzes": 0,
                "total_participants": 0,
                "total_attempts": 0,
                "average_score": 0,
                "best_score": 0,
                "quizzes_with_participants": 0
            },
            "quiz_details": []
        }), 500

# Route pour obtenir les détails des participants d'un quiz spécifique
@app.route('/api/quiz/<int:quiz_id>/participants_detailed')
@login_required
def get_quiz_participants_detailed(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    
    # Vérifier que l'utilisateur est le créateur du quiz
    if quiz.user_id != current_user.id:
        return jsonify({"error": "Non autorisé"}), 403
    
    attempts = QuizAttempt.query.filter_by(quiz_id=quiz_id)\
        .options(joinedload(QuizAttempt.user))\
        .order_by(QuizAttempt.score.desc())\
        .all()
    
    participants_data = []
    
    for attempt in attempts:
        # Calculer le temps formaté
        minutes = attempt.time_taken // 60
        seconds = attempt.time_taken % 60
        time_formatted = f"{minutes:02d}:{seconds:02d}"
        
        # Déterminer le classement
        score_class = "score-excellent" if attempt.score >= 80 else \
                    "score-good" if attempt.score >= 60 else \
                    "score-average" if attempt.score >= 40 else "score-poor"
        
        participants_data.append({
            "user_id": attempt.user.id,
            "username": attempt.user.username,
            "user_avatar": attempt.user.avatar_url,
            "score": round(attempt.score, 1),
            "time_taken": time_formatted,
            "time_seconds": attempt.time_taken,
            "completed_at": attempt.completed_at.strftime("%d/%m/%Y à %H:%M"),
            "score_class": score_class,
            "rank": len([a for a in attempts if a.score > attempt.score]) + 1
        })
    
    return jsonify({
        "quiz_title": quiz.title,
        "total_questions": len(quiz.questions),
        "participants": participants_data
    })

@app.route('/api/quiz', methods=['POST'])
@login_required
def create_quiz():
    try:
        data = request.get_json()
        logger.info(f"📝 Création quiz: {data['title']}")
        
        new_quiz = Quiz(
            user_id=current_user.id,
            title=data['title'],
            subject=data['subject'],
            description=data.get('description', ''),
            time_limit=data.get('time_limit', 0),
            is_public=data.get('is_public', True)
        )
        
        db.session.add(new_quiz)
        db.session.flush()
        
        for i, q_data in enumerate(data['questions']):
            question = Question(
                quiz_id=new_quiz.id,
                question_text=q_data['question_text'],
                question_type=q_data['question_type'],
                options=q_data['options'],
                correct_answer=q_data['correct_answer'],
                explanation=q_data.get('explanation', ''),
                order=i
            )
            db.session.add(question)
        
        db.session.commit()
        
        # 🔥 NOTIFICATION : Créer des notifications pour les utilisateurs de la même filière
        if new_quiz.is_public and current_user.profile:
            users_same_year_and_field = User.query.join(Profile).filter(
                Profile.year_of_study == current_user.profile.year_of_study,
                Profile.field_of_study == current_user.profile.field_of_study,
                User.is_active == True,
                User.id != current_user.id  # Exclure l'utilisateur actuel
            ).all()
            
            for user in users_same_year_and_field:
                notification = QuizNotification(
                    user_id=user.id,
                    quiz_id=new_quiz.id,
                    message=f"{current_user.username} a créé un nouveau quiz : {new_quiz.title}",
                    notification_type='quiz'
                )
                db.session.add(notification)
            
            db.session.commit()
            logger.info(f"✅ {len(users_same_year_and_field)} notifications quiz créées")
        
        return jsonify({"success": True, "quiz_id": new_quiz.id})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ Erreur création quiz: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/flashcard', methods=['POST'])
@login_required
def create_flashcard():
    try:
        data = request.get_json()
        logger.info(f"📝 Création flashcards: {data['title']}")
        
        new_flashcard = Flashcard(
            user_id=current_user.id,
            title=data['title'],
            subject=data['subject'],
            description=data.get('description', ''),
            is_public=data.get('is_public', True)
        )
        
        db.session.add(new_flashcard)
        db.session.flush()
        
        for card_data in data['cards']:
            card = FlashcardItem(
                flashcard_id=new_flashcard.id,
                front_content=card_data['front_content'],
                back_content=card_data['back_content'],
                order=card_data.get('order', 0)
            )
            db.session.add(card)
        
        db.session.commit()
        
        # 🔥 NOTIFICATION : Créer des notifications pour les flashcards
        if new_flashcard.is_public and current_user.profile:
            users_same_year_and_field = User.query.join(Profile).filter(
                Profile.year_of_study == current_user.profile.year_of_study,
                Profile.field_of_study == current_user.profile.field_of_study,
                User.is_active == True,
                User.id != current_user.id
            ).all()
            
            for user in users_same_year_and_field:
                notification = QuizNotification(
                    user_id=user.id,
                    flashcard_id=new_flashcard.id,
                    message=f"{current_user.username} a créé de nouvelles flashcards : {new_flashcard.title}",
                    notification_type='flashcard'
                )
                db.session.add(notification)
            
            db.session.commit()
            logger.info(f"✅ {len(users_same_year_and_field)} notifications flashcards créées")
        
        return jsonify({"success": True, "flashcard_id": new_flashcard.id})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ Erreur création flashcards: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


# Obtenir les questions d'un quiz
@app.route('/api/quiz/<int:quiz_id>/questions')
@login_required
def get_quiz_questions(quiz_id):
    questions = Question.query.filter_by(quiz_id=quiz_id).order_by(Question.order).all()
    
    return jsonify([{
        "id": q.id,
        "question_text": q.question_text,
        "question_type": q.question_type,
        "options": q.options,
        "explanation": q.explanation,
        "order": q.order
    } for q in questions])

# Obtenir les cartes d'une flashcard
@app.route('/api/flashcard/<int:flashcard_id>/cards')
@login_required
def get_flashcard_cards(flashcard_id):
    cards = FlashcardItem.query.filter_by(flashcard_id=flashcard_id).order_by(FlashcardItem.order).all()
    
    return jsonify([{
        "id": c.id,
        "front_content": c.front_content,
        "back_content": c.back_content,
        "order": c.order
    } for c in cards])

# Soumettre un quiz
@app.route('/api/quiz/<int:quiz_id>/submit', methods=['POST'])
@login_required
def submit_quiz(quiz_id):
    data = request.get_json()
    answers = data.get('answers', {})
    
    quiz = Quiz.query.get_or_404(quiz_id)
    questions = Question.query.filter_by(quiz_id=quiz_id).all()
    
    correct_count = 0
    results = {}
    
    for question in questions:
        user_answer = answers.get(str(question.id))
        is_correct = user_answer == question.correct_answer
        results[str(question.id)] = {
            "correct": is_correct,
            "correct_answer": question.correct_answer,
            "explanation": question.explanation
        }
        if is_correct:
            correct_count += 1
    
    score = (correct_count / len(questions)) * 100 if questions else 0
    
    attempt = QuizAttempt(
        user_id=current_user.id,
        quiz_id=quiz_id,
        score=score,
        total_questions=len(questions),
        time_taken=data.get('time_taken', 0)
    )
    db.session.add(attempt)
    db.session.commit()
    
    return jsonify({
        "score": score,
        "correct_count": correct_count,
        "total_questions": len(questions),
        "results": results
    })

# Supprimer un quiz
@app.route('/api/quiz/<int:quiz_id>', methods=['DELETE'])
@login_required
def delete_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    
    if quiz.user_id != current_user.id:
        return jsonify({"error": "Non autorisé"}), 403
    
    db.session.delete(quiz)
    db.session.commit()
    
    return jsonify({"success": True})

# Supprimer des flashcards
@app.route('/api/flashcard/<int:flashcard_id>', methods=['DELETE'])
@login_required
def delete_flashcard(flashcard_id):
    flashcard = Flashcard.query.get_or_404(flashcard_id)
    
    if flashcard.user_id != current_user.id:
        return jsonify({"error": "Non autorisé"}), 403
    
    db.session.delete(flashcard)
    db.session.commit()
    
    return jsonify({"success": True})


# Supprimer un commentaire (propriétaire seulement)
@app.route('/api/comment/<int:comment_id>', methods=['DELETE'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if comment.user_id != current_user.id:
        return jsonify({"error": "Non autorisé"}), 403
    try:
        db.session.delete(comment)
        db.session.commit()
        return jsonify({"success": True})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erreur suppression commentaire: {e}")
        return jsonify({"error": "Erreur serveur"}), 500

from functools import wraps
# -------------------- Configuration Clé API --------------------
API_KEYS = {
    "edushare_admin_2024": "admin",  # Clé: Valeur (vous pouvez avoir plusieurs clés)
}

def require_api_key(f):
    """Décorateur pour vérifier la clé API"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        
        if not api_key:
            return jsonify({"success": False, "error": "Clé API manquante"}), 401
        
        if api_key not in API_KEYS:
            return jsonify({"success": False, "error": "Clé API invalide"}), 401
        
        return f(*args, **kwargs)
    return decorated_function

# -------------------- Routes API Publiques avec Clé API --------------------
def validate_and_fix_question_data(question_data):
    """Valide et corrige les données des questions"""
    fixed_data = question_data.copy()
    
    # S'assurer que les options sont une liste valide
    options = fixed_data.get('options', [])
    
    if not isinstance(options, list):
        fixed_data['options'] = []
    else:
        # Filtrer les valeurs None, 'undefined' (toutes casses) ou vides
        cleaned_options = []
        for opt in options:
            if opt is None:
                continue
            if isinstance(opt, str) and opt.strip().lower() == "undefined":
                continue
            if isinstance(opt, str) and opt.strip() == "":
                continue
            cleaned_options.append(opt)

        fixed_data['options'] = cleaned_options

        # Si toutes les options sont invalides, créer des options par défaut
        if len(fixed_data['options']) == 0:
            fixed_data['options'] = ["Option A", "Option B", "Option C", "Option D"]
    
    # Normaliser les options en un dictionnaire {a:..., b:..., c:..., d:...}
    # Accepter soit une liste soit un dict en entrée
    normalized_options = {}
    try:
        # Si options est une dict déjà, respectons l'ordre a,b,c,d si présent
        if isinstance(question_data.get('options'), dict):
            for key in ['a', 'b', 'c', 'd']:
                val = question_data['options'].get(key)
                if val is not None and not (isinstance(val, str) and val.strip().lower() == 'undefined') and not (isinstance(val, str) and val.strip() == ''):
                    normalized_options[key] = val
        else:
            # options is list-like
            opts = fixed_data.get('options', [])
            # already cleaned list in fixed_data['options'] above
            for idx, val in enumerate(fixed_data['options']):
                if idx == 0:
                    normalized_options['a'] = val
                elif idx == 1:
                    normalized_options['b'] = val
                elif idx == 2:
                    normalized_options['c'] = val
                elif idx == 3:
                    normalized_options['d'] = val
    except Exception:
        # Fallback: create default options
        normalized_options = {'a': 'Option A', 'b': 'Option B', 'c': 'Option C', 'd': 'Option D'}

    # Garantir au moins a et b
    if 'a' not in normalized_options:
        normalized_options['a'] = 'Option A'
    if 'b' not in normalized_options:
        normalized_options['b'] = 'Option B'

    fixed_data['options'] = normalized_options

    # S'assurer que la réponse correcte est valide et la convertir en clé ('a'|'b'|'c'|'d')
    correct_answer = fixed_data.get('correct_answer')
    chosen_key = None

    # Normalize candidate
    if isinstance(correct_answer, str):
        ca = correct_answer.strip()
        # if the client provided the textual value, find the matching key
        for k, v in normalized_options.items():
            # compare stripped strings
            try:
                if isinstance(v, str) and v.strip() == ca:
                    chosen_key = k
                    break
            except Exception:
                continue

        # if client already provided a key like 'a' or 'b', accept it if present
        if ca.lower() in normalized_options.keys():
            chosen_key = ca.lower()

    # default to 'a' if no match
    if not chosen_key:
        chosen_key = list(normalized_options.keys())[0]

    fixed_data['correct_answer'] = chosen_key
    
    return fixed_data

@app.route('/api/public/quiz', methods=['POST'])
@require_api_key
def api_public_create_quiz():
    """
    Route API publique pour créer un quiz pour n'importe quel utilisateur
    Authentification par clé API
    """
    try:
        data = request.get_json()
        
        # Récupérer l'ID de l'utilisateur cible
        target_user_id = data.get('user_id')
        if not target_user_id:
            return jsonify({"success": False, "error": "user_id requis"}), 400
        
        # Vérifier que l'utilisateur cible existe
        target_user = User.query.get(target_user_id)
        if not target_user:
            return jsonify({"success": False, "error": "Utilisateur non trouvé"}), 404
        
        # Créer le quiz
        new_quiz = Quiz(
            user_id=target_user_id,
            title=data['title'],
            subject=data['subject'],
            description=data.get('description', ''),
            time_limit=data.get('time_limit', 0),
            is_public=data.get('is_public', True)
        )
        
        db.session.add(new_quiz)
        db.session.flush()
        
        # Ajouter les questions
        for i, q_data in enumerate(data.get('questions', [])):
            # LOG: dump raw incoming question payload to help debug 'undefined' answers
            try:
                logger.debug(f"Incoming question payload (index={i}): {q_data!r}")
            except Exception:
                pass

            # VALIDER ET CORRIGER LES DONNÉES DE LA QUESTION
            q_data = validate_and_fix_question_data(q_data)

            try:
                logger.debug(f"Validated question payload (index={i}): {q_data!r}")
            except Exception:
                pass

            question = Question(
                quiz_id=new_quiz.id,
                question_text=q_data['question_text'],
                question_type=q_data.get('question_type', 'multiple_choice'),
                options=q_data['options'],  # ← Utiliser les options corrigées
                correct_answer=q_data['correct_answer'],
                explanation=q_data.get('explanation', ''),
                order=i
            )
            db.session.add(question)
        
        db.session.commit()
        # Après commit, loguer les réponses correctes stockées pour vérification
        try:
            saved_questions = Question.query.filter_by(quiz_id=new_quiz.id).order_by(Question.order).all()
            for sq in saved_questions:
                logger.info(f"Saved question id={sq.id} correct_answer={sq.correct_answer!r}")
        except Exception as _e:
            logger.warning(f"Impossible de lister les questions enregistrées: {_e}")
        # 🔥 NOTIFICATION : Créer des notifications pour les utilisateurs de la même filière
        try:
            if new_quiz.is_public and target_user.profile:
                users_same_year_and_field = User.query.join(Profile).filter(
                    Profile.year_of_study == target_user.profile.year_of_study,
                    Profile.field_of_study == target_user.profile.field_of_study,
                    User.is_active == True,
                    User.id != target_user.id
                ).all()

                for user in users_same_year_and_field:
                    notification = QuizNotification(
                        user_id=user.id,
                        quiz_id=new_quiz.id,
                        message=f"{target_user.username} a créé un nouveau quiz : {new_quiz.title}",
                        notification_type='quiz'
                    )
                    db.session.add(notification)

                db.session.commit()
                logger.info(f"✅ {len(users_same_year_and_field)} notifications quiz créées via API")
        except Exception as _e:
            # Ne pas faire échouer la création principale si la notification échoue
            db.session.rollback()
            logger.error(f"⚠️ Erreur lors de la création des notifications quiz API: {_e}")

        logger.info(f"✅ Quiz créé via API pour l'utilisateur {target_user_id}: {new_quiz.title}")
        return jsonify({
            "success": True, 
            "quiz_id": new_quiz.id,
            "message": f"Quiz créé avec succès pour {target_user.username}",
            "data": {
                "quiz_id": new_quiz.id,
                "title": new_quiz.title,
                "subject": new_quiz.subject,
                "question_count": len(data.get('questions', [])),
                "created_for": target_user.username
            }
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ Erreur création quiz API: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/public/flashcard', methods=['POST'])
@require_api_key
def api_public_create_flashcard():
    """
    Route API publique pour créer des flashcards pour n'importe quel utilisateur
    Authentification par clé API
    """
    try:
        data = request.get_json()
        
        # Récupérer l'ID de l'utilisateur cible
        target_user_id = data.get('user_id')
        if not target_user_id:
            return jsonify({"success": False, "error": "user_id requis"}), 400
        
        # Vérifier que l'utilisateur cible existe
        target_user = User.query.get(target_user_id)
        if not target_user:
            return jsonify({"success": False, "error": "Utilisateur non trouvé"}), 404
        
        # Créer la flashcard
        new_flashcard = Flashcard(
            user_id=target_user_id,
            title=data['title'],
            subject=data['subject'],
            description=data.get('description', ''),
            is_public=data.get('is_public', True)
        )
        
        db.session.add(new_flashcard)
        db.session.flush()
        
        # Ajouter les cartes
        for i, card_data in enumerate(data.get('cards', [])):
            card = FlashcardItem(
                flashcard_id=new_flashcard.id,
                front_content=card_data['front_content'],
                back_content=card_data['back_content'],
                order=i
            )
            db.session.add(card)
        
        db.session.commit()
        # 🔥 NOTIFICATION : Créer des notifications pour les flashcards
        try:
            if new_flashcard.is_public and target_user.profile:
                users_same_year_and_field = User.query.join(Profile).filter(
                    Profile.year_of_study == target_user.profile.year_of_study,
                    Profile.field_of_study == target_user.profile.field_of_study,
                    User.is_active == True,
                    User.id != target_user.id
                ).all()

                for user in users_same_year_and_field:
                    notification = QuizNotification(
                        user_id=user.id,
                        flashcard_id=new_flashcard.id,
                        message=f"{target_user.username} a créé de nouvelles flashcards : {new_flashcard.title}",
                        notification_type='flashcard'
                    )
                    db.session.add(notification)

                db.session.commit()
                logger.info(f"✅ {len(users_same_year_and_field)} notifications flashcards créées via API")
        except Exception as _e:
            db.session.rollback()
            logger.error(f"⚠️ Erreur lors de la création des notifications flashcards API: {_e}")

        logger.info(f"✅ Flashcards créées via API pour l'utilisateur {target_user_id}: {new_flashcard.title}")
        return jsonify({
            "success": True, 
            "flashcard_id": new_flashcard.id,
            "message": f"Flashcards créées avec succès pour {target_user.username}",
            "data": {
                "flashcard_id": new_flashcard.id,
                "title": new_flashcard.title,
                "subject": new_flashcard.subject,
                "card_count": len(data.get('cards', [])),
                "created_for": target_user.username
            }
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ Erreur création flashcards API: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/public/users', methods=['GET'])
@require_api_key
def api_public_get_users():
    """
    Route API publique pour obtenir la liste des utilisateurs
    """
    try:
        # Récupérer les paramètres de recherche
        search = request.args.get('search', '')
        limit = request.args.get('limit', 50, type=int)
        
        # Construire la requête
        query = User.query
        
        if search:
            query = query.filter(
                db.or_(
                    User.username.ilike(f'%{search}%'),
                    User.email.ilike(f'%{search}%')
                )
            )
        
        users = query.order_by(User.created_at.desc()).limit(limit).all()
        
        return jsonify({
            "success": True,
            "users": [{
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "created_at": user.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "profile_completed": bool(user.profile),
                "quiz_count": len(user.quizzes),
                "flashcard_count": len(user.flashcards)
            } for user in users]
        })
        
    except Exception as e:
        logger.error(f"❌ Erreur récupération utilisateurs API: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/public/batch_quizzes', methods=['POST'])
@require_api_key
def api_public_batch_create_quizzes():
    """
    Route API pour créer plusieurs quizzes en une seule requête
    """
    try:
        data = request.get_json()
        quizzes_data = data.get('quizzes', [])
        
        results = []
        
        for quiz_data in quizzes_data:
            target_user_id = quiz_data.get('user_id')
            if not target_user_id:
                results.append({"success": False, "error": "user_id manquant", "title": quiz_data.get('title')})
                continue
            
            target_user = User.query.get(target_user_id)
            if not target_user:
                results.append({"success": False, "error": "Utilisateur non trouvé", "user_id": target_user_id})
                continue
            
            # Créer le quiz
            new_quiz = Quiz(
                user_id=target_user_id,
                title=quiz_data['title'],
                subject=quiz_data['subject'],
                description=quiz_data.get('description', ''),
                time_limit=quiz_data.get('time_limit', 0),
                is_public=quiz_data.get('is_public', True)
            )
            
            db.session.add(new_quiz)
            db.session.flush()
            
            # Ajouter les questions
            for i, q_data in enumerate(quiz_data.get('questions', [])):
                question = Question(
                    quiz_id=new_quiz.id,
                    question_text=q_data['question_text'],
                    question_type=q_data.get('question_type', 'multiple_choice'),
                    options=q_data.get('options', []),
                    correct_answer=q_data['correct_answer'],
                    explanation=q_data.get('explanation', ''),
                    order=i
                )
                db.session.add(question)
            # Créer notifications pour ce quiz si public
            try:
                if new_quiz.is_public and target_user.profile:
                    users_same_year_and_field = User.query.join(Profile).filter(
                        Profile.year_of_study == target_user.profile.year_of_study,
                        Profile.field_of_study == target_user.profile.field_of_study,
                        User.is_active == True,
                        User.id != target_user.id
                    ).all()

                    for user in users_same_year_and_field:
                        notification = QuizNotification(
                            user_id=user.id,
                            quiz_id=new_quiz.id,
                            message=f"{target_user.username} a créé un nouveau quiz : {new_quiz.title}",
                            notification_type='quiz'
                        )
                        db.session.add(notification)
            except Exception as _e:
                logger.error(f"⚠️ Erreur notification batch quiz: {_e}")
            
            results.append({
                "success": True,
                "quiz_id": new_quiz.id,
                "title": new_quiz.title,
                "user_id": target_user_id,
                "username": target_user.username
            })
        
        db.session.commit()
        
        return jsonify({
            "success": True,
            "message": f"{len([r for r in results if r['success']])} quizzes créés avec succès",
            "results": results
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ Erreur création batch quizzes API: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/public/batch_flashcards', methods=['POST'])
@require_api_key
def api_public_batch_create_flashcards():
    """
    Route API pour créer plusieurs flashcards en une seule requête
    """
    try:
        data = request.get_json()
        flashcards_data = data.get('flashcards', [])
        
        results = []
        
        for flashcard_data in flashcards_data:
            target_user_id = flashcard_data.get('user_id')
            if not target_user_id:
                results.append({"success": False, "error": "user_id manquant", "title": flashcard_data.get('title')})
                continue
            
            target_user = User.query.get(target_user_id)
            if not target_user:
                results.append({"success": False, "error": "Utilisateur non trouvé", "user_id": target_user_id})
                continue
            
            # Créer la flashcard
            new_flashcard = Flashcard(
                user_id=target_user_id,
                title=flashcard_data['title'],
                subject=flashcard_data['subject'],
                description=flashcard_data.get('description', ''),
                is_public=flashcard_data.get('is_public', True)
            )
            
            db.session.add(new_flashcard)
            db.session.flush()
            
            # Ajouter les cartes
            for i, card_data in enumerate(flashcard_data.get('cards', [])):
                card = FlashcardItem(
                    flashcard_id=new_flashcard.id,
                    front_content=card_data['front_content'],
                    back_content=card_data['back_content'],
                    order=i
                )
                db.session.add(card)
            
            results.append({
                "success": True,
                "flashcard_id": new_flashcard.id,
                "title": new_flashcard.title,
                "user_id": target_user_id,
                "username": target_user.username
            })
        
        db.session.commit()
        
        return jsonify({
            "success": True,
            "message": f"{len([r for r in results if r['success']])} flashcards créées avec succès",
            "results": results
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ Erreur création batch flashcards API: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

# Route pour vérifier la santé de l'API
@app.route('/api/public/health', methods=['GET'])
@require_api_key
def api_public_health():
    """Vérifier que l'API fonctionne"""
    # Retour propre sans caractères non-ASCII invisibles
    return jsonify({
        "success": True,
        "message": "API EduShare fonctionnelle",
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "total_users": User.query.count(),
        "total_quizzes": Quiz.query.count(),
        "total_flashcards": Flashcard.query.count()
    })


# Supprimer une ressource (propriétaire seulement)
@app.route('/api/ressource/<int:ressource_id>', methods=['DELETE'])
@login_required
def delete_ressource(ressource_id):
    try:
        # Vérifier si la ressource existe
        res = Ressource.query.get(ressource_id)
        if not res:
            logger.error(f"Ressource non trouvée: {ressource_id}")
            return jsonify({"error": "Ressource non trouvée"}), 404
            
        # Vérifier que l'utilisateur est le propriétaire
        if res.user_id != current_user.id:
            logger.warning(f"Tentative de suppression non autorisée - Utilisateur: {current_user.id}, Propriétaire: {res.user_id}")
            return jsonify({"error": "Non autorisé"}), 403
            
        # Supprimer d'abord les entrées liées dans la table SavedRessource
        SavedRessource.query.filter_by(ressource_id=ressource_id).delete()
        
        # Supprimer les notifications liées à cette ressource
        Notification.query.filter_by(ressource_id=ressource_id).delete()
        
        # Supprimer la ressource
        db.session.delete(res)
        db.session.commit()
        
        logger.info(f"Ressource {ressource_id} supprimée avec succès par l'utilisateur {current_user.id}")
        return jsonify({"success": True})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erreur lors de la suppression de la ressource {ressource_id}: {str(e)}", exc_info=True)
        return jsonify({"error": "Une erreur est survenue lors de la suppression"}), 500

# Notifications pour quiz/flashcards
@app.route('/api/quiz_notifications')
@login_required
def api_quiz_notifications():
    notifications = QuizNotification.query.filter_by(user_id=current_user.id)\
        .options(joinedload(QuizNotification.quiz), joinedload(QuizNotification.flashcard))\
        .order_by(QuizNotification.created_at.desc())\
        .limit(20)\
        .all()
    
    return jsonify([{
        "id": n.id,
        "message": n.message,
        "is_read": n.is_read,
        "created_at": n.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "quiz_id": n.quiz_id,
        "flashcard_id": n.flashcard_id,
        "notification_type": n.notification_type,
        "quiz_title": n.quiz.title if n.quiz else None,
        "flashcard_title": n.flashcard.title if n.flashcard else None
    } for n in notifications])

@app.route('/api/quiz_notifications/read/<int:notification_id>', methods=['POST'])
@login_required
def mark_quiz_notification_read(notification_id):
    notification = QuizNotification.query.filter_by(id=notification_id, user_id=current_user.id).first()
    if notification:
        notification.is_read = True
        db.session.commit()
        return jsonify({"success": True})
    return jsonify({"error": "Notification non trouvée"}), 404

@app.route('/api/quiz_notifications/read_all', methods=['POST'])
@login_required
def mark_all_quiz_notifications_read():
    QuizNotification.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True})
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/quiz_notifications/count')
@login_required
def unread_quiz_notifications_count():
    count = QuizNotification.query.filter_by(user_id=current_user.id, is_read=False).count()
    return jsonify({"count": count})


# Route pour obtenir les détails d'un quiz (modification)
@app.route('/api/quiz/<int:quiz_id>/edit')
@login_required
def get_quiz_for_edit(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    
    # Vérifier que l'utilisateur est le créateur
    if quiz.user_id != current_user.id:
        return jsonify({"error": "Non autorisé"}), 403
    
    return jsonify({
        "id": quiz.id,
        "title": quiz.title,
        "subject": quiz.subject,
        "description": quiz.description,
        "time_limit": quiz.time_limit,
        "is_public": quiz.is_public,
        "questions": [{
            "id": q.id,
            "question_text": q.question_text,
            "question_type": q.question_type,
            "options": q.options,
            "correct_answer": q.correct_answer,
            "explanation": q.explanation,
            "order": q.order
        } for q in quiz.questions]
    })

# Route pour modifier un quiz
@app.route('/api/quiz/<int:quiz_id>', methods=['PUT'])
@login_required
def update_quiz(quiz_id):
    try:
        quiz = Quiz.query.get_or_404(quiz_id)
        
        # Vérifier que l'utilisateur est le créateur
        if quiz.user_id != current_user.id:
            return jsonify({"error": "Non autorisé"}), 403
        
        data = request.get_json()
        
        # Mettre à jour le quiz
        quiz.title = data['title']
        quiz.subject = data['subject']
        quiz.description = data.get('description', '')
        quiz.time_limit = data.get('time_limit', 0)
        quiz.is_public = data.get('is_public', True)
        
        # Supprimer les anciennes questions
        Question.query.filter_by(quiz_id=quiz_id).delete()
        
        # Ajouter les nouvelles questions
        for i, q_data in enumerate(data['questions']):
            question = Question(
                quiz_id=quiz.id,
                question_text=q_data['question_text'],
                question_type=q_data['question_type'],
                options=q_data['options'],
                correct_answer=q_data['correct_answer'],
                explanation=q_data.get('explanation', ''),
                order=i
            )
            db.session.add(question)
        
        db.session.commit()
        
        return jsonify({"success": True, "quiz_id": quiz.id})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ Erreur modification quiz: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

# Route pour obtenir les détails d'une flashcard (modification)
@app.route('/api/flashcard/<int:flashcard_id>/edit')
@login_required
def get_flashcard_for_edit(flashcard_id):
    flashcard = Flashcard.query.get_or_404(flashcard_id)
    
    # Vérifier que l'utilisateur est le créateur
    if flashcard.user_id != current_user.id:
        return jsonify({"error": "Non autorisé"}), 403
    
    return jsonify({
        "id": flashcard.id,
        "title": flashcard.title,
        "subject": flashcard.subject,
        "description": flashcard.description,
        "is_public": flashcard.is_public,
        "cards": [{
            "id": c.id,
            "front_content": c.front_content,
            "back_content": c.back_content,
            "order": c.order
        } for c in flashcard.cards]
    })

# Route pour modifier des flashcards
@app.route('/api/flashcard/<int:flashcard_id>', methods=['PUT'])
@login_required
def update_flashcard(flashcard_id):
    try:
        flashcard = Flashcard.query.get_or_404(flashcard_id)
        
        # Vérifier que l'utilisateur est le créateur
        if flashcard.user_id != current_user.id:
            return jsonify({"error": "Non autorisé"}), 403
        
        data = request.get_json()
        
        # Mettre à jour la flashcard
        flashcard.title = data['title']
        flashcard.subject = data['subject']
        flashcard.description = data.get('description', '')
        flashcard.is_public = data.get('is_public', True)
        
        # Supprimer les anciennes cartes
        FlashcardItem.query.filter_by(flashcard_id=flashcard_id).delete()
        
        # Ajouter les nouvelles cartes
        for card_data in data['cards']:
            card = FlashcardItem(
                flashcard_id=flashcard.id,
                front_content=card_data['front_content'],
                back_content=card_data['back_content'],
                order=card_data.get('order', 0)
            )
            db.session.add(card)
        
        db.session.commit()
        
        return jsonify({"success": True, "flashcard_id": flashcard.id})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ Erreur modification flashcards: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

# -------------------- Routes OAuth --------------------
@app.route('/youtube_auth')
@login_required
def youtube_auth():
    if current_user.youtube_credentials:
        return redirect(url_for('share_youtube_video'))

    flow = Flow.from_client_config(
        get_client_config(),
        scopes=YOUTUBE_SCOPES,
        redirect_uri=url_for('youtube_oauth2callback', _external=True)
    )
    auth_url, _ = flow.authorization_url(prompt="consent")
    return redirect(auth_url)

@app.route('/youtube_oauth2callback')
@login_required
def youtube_oauth2callback():
    flow = Flow.from_client_config(
        get_client_config(),
        scopes=YOUTUBE_SCOPES,
        redirect_uri=url_for('youtube_oauth2callback', _external=True)
    )
    flow.fetch_token(authorization_response=request.url)

    current_user.youtube_credentials = pickle.dumps(flow.credentials)
    db.session.commit()

    flash("✅ Auth YouTube réussie !", "success")
    return redirect(url_for('share_youtube_video'))

@app.route('/share_youtube_video', methods=['GET', 'POST'])
@login_required
def share_youtube_video():
    if not current_user.youtube_credentials:
        return redirect(url_for('youtube_auth'))

    if request.method == 'POST':
        title = request.form.get('title')
        subject = request.form.get('subject')
        video_file = request.files.get('video')

        if not title or not subject or not video_file:
            flash("Tous les champs sont requis.", "danger")
            return render_template('share_youtube.html')

        fd, temp_path = tempfile.mkstemp(suffix=".mp4")
        with os.fdopen(fd, 'wb') as tmp:
            video_file.save(tmp)

        try:
            credentials = pickle.loads(current_user.youtube_credentials)
            youtube = build("youtube", "v3", credentials=credentials)

            body = {
                "snippet": {
                    "title": title,
                    "description": f"Partagée via Edushare - Matière : {subject}",
                    "tags": ["edushare", subject.lower()],
                    "categoryId": "27"
                },
                "status": {"privacyStatus": "unlisted"}
            }

            insert_request = youtube.videos().insert(
                part="snippet,status",
                body=body,
                media_body=MediaFileUpload(temp_path, chunksize=-1, resumable=True)
            )
            response = insert_request.execute()

            video_id = response["id"]
            embed_url = f"https://www.youtube.com/embed/{video_id}"
            watch_url = f"https://www.youtube.com/watch?v={video_id}"

            new_ressource = Ressource(
                user_id=current_user.id,
                title=title,
                subject=subject,
                file_url=embed_url,
                download_url=watch_url,
                file_type="youtube",
                page_count=0
            )
            db.session.add(new_ressource)
            db.session.commit()

            if current_user.profile and current_user.profile.year_of_study and current_user.profile.field_of_study:
                users_same_year_and_field = User.query.join(Profile).filter(
                    Profile.year_of_study == current_user.profile.year_of_study,
                    Profile.field_of_study == current_user.profile.field_of_study,
                    User.is_active == True
                ).all()
                
                logger.info(f"📢 Création de notifications YouTube pour {len(users_same_year_and_field)} utilisateurs")
                
                for user in users_same_year_and_field:
                    if user.id == current_user.id:
                        message = f"Vous avez partagé une nouvelle vidéo YouTube : {title}"
                    else:
                        message = f"{current_user.username} a partagé une nouvelle vidéo YouTube : {title}"
                    
                    notification = Notification(
                        user_id=user.id,
                        ressource_id=new_ressource.id,
                        message=message
                    )
                    db.session.add(notification)
                
                db.session.commit()
                logger.info(f"✅ {len(users_same_year_and_field)} notifications YouTube créées avec succès")

            flash("✅ Vidéo uploadée sur YouTube et partagée !", "success")
            return redirect(url_for('videos'))

        except Exception as e:
            db.session.rollback()
            logger.error(f"❌ Échec de l'upload YouTube : {e}")
            flash(f"❌ Échec de l'upload YouTube : {e}", "danger")
            return render_template('share_youtube.html')

        finally:
            try:
                os.remove(temp_path)
            except Exception as e:
                logger.warning(f"Impossible de supprimer le fichier temporaire: {e}")

    return render_template('share_youtube.html')

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

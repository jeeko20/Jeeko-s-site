import os
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template,session, request, redirect,Response, url_for, flash, jsonify,send_from_directory
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
database_url = os.environ.get("DATABASE_URL")
if not database_url:
    raise RuntimeError("❌ DATABASE_URL introuvable !")
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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
    youtube_credentials = db.Column(db.LargeBinary, nullable=True)  # <-- ajout
    security_question = db.Column(db.String(200))  # Nouveau
    security_answer = db.Column(db.String(200))    # Nouveau


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
    field_of_study = db.Column(db.String(100))  # Nouveau champ : filière
    custom_field = db.Column(db.String(100))    # Pour "autre" filière
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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('comments', lazy=True))
    discussion = db.relationship('Discussion', backref=db.backref('comments', lazy=True, cascade="all, delete-orphan"))

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

# -------------------- Modèles --------------------
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ressource_id = db.Column(db.Integer, db.ForeignKey('ressource.id'), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('notifications', lazy=True))
    ressource = db.relationship('Ressource', backref=db.backref('notifications', lazy=True))

def fix_cloudinary_url(url):
    """Corrige les URLs Cloudinary si nécessaire"""
    if not url:
        return "https://cdn.pixabay.com/photo/2024/06/22/22/55/man-8847064_640.jpg"
    
    # Si c'est déjà une URL complète, la retourner telle quelle
    if url.startswith('http'):
        return url
    
    # Si c'est un public_id Cloudinary, construire l'URL complète
    if '/' in url and '.' in url:
        # Nettoyer le public_id
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
        security_question = request.form['security_question']  # Nouveau
        security_answer = request.form['security_answer']      # Nouveau
        
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
                security_answer=security_answer.lower()  # Stocke en minuscule
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
            # Redirige vers la page de question secrète
            return redirect(url_for('security_question', user_id=user.id))
        else:
            flash('Aucun compte trouvé avec cet email.', 'danger')
    
    return render_template('forgot_password.html')

@app.route('/security_question/<int:user_id>', methods=['GET', 'POST'])
def security_question(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        answer = request.form.get('security_answer')
        
        # Vérifie la réponse (case insensitive)
        if answer and answer.lower() == user.security_answer.lower():
            # Génère un token simple pour réinitialisation
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
    # Vérifie le token de session
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
            # Met à jour le mot de passe
            user.password = generate_password_hash(password)
            db.session.commit()
            
            # Nettoie la session
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

# Passe la fonction aux templates
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
        field_of_study = request.form.get('field_of_study')  # Nouveau
        custom_field = request.form.get('custom_field')      # Nouveau
        avatar_file = request.files.get('avatar')
        avatar_path = current_user.profile.avatar_path if current_user.profile else None
        
        # Vérification email unique
        email_exist = Profile.query.filter(
            Profile.email == email, 
            Profile.user_id != current_user.id
        ).first()
        if email_exist:
            flash('Cet email est déjà pris', 'danger')
            return redirect(url_for('profile'))

        # Gestion avatar
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

        # Mise à jour ou création du profil
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


# -------------------- Accès à la communauté : vérifie profil --------------------
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

MAX_FILE_SIZE = 50 * 1024 * 1024  # 100 Mo

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

        # Sauvegarder d'abord les ressources
        db.session.commit()
        
        # Créer les notifications
        if uploaded_count > 0 and current_user.profile and current_user.profile.year_of_study and current_user.profile.field_of_study:
            new_ressources = Ressource.query.filter_by(
                user_id=current_user.id, 
                title=title, 
                subject=subject
            ).order_by(Ressource.created_at.desc()).limit(uploaded_count).all()
            
            # 🔥 CORRECTION FINALE
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


# ------------------- DEBUG -------------------
@app.route('/debug/user_notifications')
@login_required
def debug_user_notifications():
    """Debug des notifications de l'utilisateur actuel"""
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
            "created_at": n.created_at.isoformat()
        } for n in notifications]
    }
    
    return jsonify(debug_info)

@app.route('/debug/cloudinary_config')
def debug_cloudinary_config():
    """Teste la configuration Cloudinary"""
    try:
        # Tester un upload simple
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

@app.route('/debug/avatars')
@login_required
def debug_avatars():
    """Debug des avatars des utilisateurs"""
    users = User.query.options(joinedload(User.profile)).all()
    
    avatars_info = []
    for user in users:
        avatar_path = user.profile.avatar_path if user.profile else None
        avatars_info.append({
            'user_id': user.id,
            'username': user.username,
            'avatar_path': avatar_path,
            'avatar_url': user.avatar_url,
            'is_full_url': avatar_path.startswith('http') if avatar_path else False
        })
    
    return jsonify(avatars_info)

@app.route('/fix/cloudinary_permissions')
@login_required
def fix_cloudinary_permissions():
    """Ré-uploader tous les avatars avec les bonnes permissions"""
    if current_user.id != 1:  # Seul l'admin
        return "Accès non autorisé", 403
    
    users = User.query.options(joinedload(User.profile)).filter(
        User.profile.has(Profile.avatar_path.isnot(None))
    ).all()
    
    fixed_count = 0
    for user in users:
        if user.profile.avatar_path and 'cloudinary.com' in user.profile.avatar_path:
            try:
                # Télécharger et ré-uploader avec les bonnes permissions
                response = requests.get(user.profile.avatar_path, timeout=10)
                if response.status_code == 200:
                    # Ré-uploader avec permissions publiques
                    new_upload = cloudinary.uploader.upload(
                        response.content,
                        folder="edushare/avatars_fixed",
                        public_id=f"avatar_fixed_{user.id}",
                        overwrite=True,
                        invalidate=True,
                        access_mode="public",
                        type="upload"
                    )
                    
                    user.profile.avatar_path = new_upload.get("secure_url")
                    fixed_count += 1
                    logger.info(f"✅ Avatar réparé pour {user.username}")
                else:
                    logger.warning(f"❌ Impossible de télécharger l'avatar de {user.username}")
                    
            except Exception as e:
                logger.error(f"❌ Erreur réparation avatar {user.username}: {e}")
                continue
    
    db.session.commit()
    
    return jsonify({
        "message": f"{fixed_count} avatars réparés avec les bonnes permissions",
        "fixed_count": fixed_count
    })

@app.route('/debug/notifications')
@login_required
def debug_notifications():
    """Route pour debugger les notifications"""
    notifications = Notification.query.all()
    users_count = User.query.count()
    current_year = current_user.profile.year_of_study if current_user.profile else None
    
    debug_info = {
        "total_notifications": len(notifications),
        "total_users": users_count,
        "current_user_year": current_year,
        "notifications": [{
            "id": n.id,
            "user_id": n.user_id,
            "message": n.message,
            "is_read": n.is_read,
            "created_at": n.created_at.isoformat()
        } for n in notifications]
    }
    
    return jsonify(debug_info)

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
        "title": r.title,
        "subject": r.subject,
        "file_type": r.file_type,
        "likes": r.likes,
        "created_at": r.created_at.isoformat(),
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
    current_field = current_user.profile.field_of_study  # Nouveau filtre

    video_types = ['mp4', 'mov', 'avi', 'mkv', 'webm','youtube']
    videos = Ressource.query.join(User).join(Profile).filter(
        Profile.year_of_study == current_year,
        Profile.field_of_study == current_field,  # Filtre par filière
        Ressource.file_type.in_(video_types)
    ).options(joinedload(Ressource.user)).order_by(Ressource.created_at.desc()).all()

    saved_ids = {sr.ressource_id for sr in SavedRessource.query.filter_by(user_id=current_user.id).all()}
    return jsonify([{
        "id": r.id,
        "title": r.title,
        "subject": r.subject,
        "file_type": r.file_type,
        "likes": r.likes,
        "created_at": r.created_at.isoformat(),
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
    current_field = current_user.profile.field_of_study  # Nouveau filtre

    query = Discussion.query.join(User).join(Profile).filter(
        Profile.year_of_study == current_year,
        Profile.field_of_study == current_field  # Filtre par filière
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
        "title": d.title,
        "subject": d.subject,
        "content": d.content,
        "likes": d.likes,
        "created_at": d.created_at.isoformat(),
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
        "created_at": new_discussion.created_at.isoformat(),
        "user_avatar": new_discussion.user.avatar_url,
        "username": new_discussion.user.username,
        "comment_count": 0
    }), 201

# -------------------- Autres routes inchangées --------------------
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
        "created_at": s.ressource.created_at.isoformat(),
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
        "created_at": r.created_at.isoformat(),
        "file_url": r.file_url,
        "download_url": r.download_url,
        "page_count": r.page_count,
        "is_video": r.file_type in ['mp4', 'mov', 'avi', 'mkv', 'webm']
    } for r in ressources])

@app.route('/api/discussion/<int:discussion_id>/comments', methods=['GET'])
def get_comments(discussion_id):
    comments = Comment.query.options(
        joinedload(Comment.user)
    ).filter_by(discussion_id=discussion_id).order_by(Comment.created_at.asc()).all()
    return jsonify([{
        "id": c.id,
        "content": c.content,
        "created_at": c.created_at.isoformat(),
        "user_avatar": c.user.avatar_url,
        "username": c.user.username
    } for c in comments])

@app.route('/api/discussion/<int:discussion_id>/comment', methods=['POST'])
@login_required
def add_comment(discussion_id):
    data = request.get_json()
    content = data.get('content')
    if not content:
        return jsonify({"error": "Contenu requis"}), 400
    new_comment = Comment(
        discussion_id=discussion_id,
        user_id=current_user.id,
        content=content
    )
    db.session.add(new_comment)
    db.session.commit()
    return jsonify({
        "id": new_comment.id,
        "content": new_comment.content,
        "created_at": new_comment.created_at.isoformat(),
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
        "created_at": n.created_at.isoformat(),
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


# -------------------- Pages --------------------
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
        
        # Créer le message pour WhatsApp
        whatsapp_message = f"*Nouveau message de contact:*%0A%0A" \
                          f"*Nom:* {name}%0A" \
                          f"*Email:* {email}%0A" \
                          f"*Sujet:* {subject}%0A" \
                          f"*Message:*%0A{message}"
        
        # Numéro WhatsApp (le tien)
        whatsapp_number = "50933970083"  # Sans le +
        
        # URL WhatsApp
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


# Liste des routes publiques à indexer
public_routes = [
    "home",
    "about",
    "profile",
    "communaute",
    "videos",
    "notes",
    "learn_html",
    "learn_css",
    "contact",
    "systeme"
]

@app.route("/sitemap.xml", methods=['GET'])
def sitemap():
    """Génère le sitemap XML dynamique"""
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







# -------------------- Routes OAuth --------------------
@app.route('/youtube_auth')
@login_required
def youtube_auth():
    """Déclenche l'authentification OAuth YouTube."""
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
    """Callback OAuth, stocke les credentials dans la DB."""
    flow = Flow.from_client_config(
        get_client_config(),
        scopes=YOUTUBE_SCOPES,
        redirect_uri=url_for('youtube_oauth2callback', _external=True)
    )
    flow.fetch_token(authorization_response=request.url)

    # Stockage sécurisé dans la DB
    current_user.youtube_credentials = pickle.dumps(flow.credentials)
    db.session.commit()

    flash("✅ Auth YouTube réussie !", "success")
    return redirect(url_for('share_youtube_video'))

@app.route('/share_youtube_video', methods=['GET', 'POST'])  # 🔥 AJOUT DE 'GET' ICI
@login_required
def share_youtube_video():
    """Upload de vidéos sur YouTube et sauvegarde dans la DB."""
    if not current_user.youtube_credentials:
        return redirect(url_for('youtube_auth'))

    if request.method == 'POST':
        title = request.form.get('title')
        subject = request.form.get('subject')
        video_file = request.files.get('video')

        if not title or not subject or not video_file:
            flash("Tous les champs sont requis.", "danger")
            return render_template('share_youtube.html')

        # Fichier temporaire
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

            # Sauvegarde dans la base de données
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
            db.session.commit()  # Sauvegarder d'abord la ressource

            # 🔔 CORRECTION : utiliser le bon nom de variable
            if current_user.profile and current_user.profile.year_of_study and current_user.profile.field_of_study:
                users_same_year_and_field = User.query.join(Profile).filter(
                    Profile.year_of_study == current_user.profile.year_of_study,
                    Profile.field_of_study == current_user.profile.field_of_study,
                    User.is_active == True
                ).all()
                
                logger.info(f"📢 Création de notifications YouTube pour {len(users_same_year_and_field)} utilisateurs")
                
                for user in users_same_year_and_field:
                    # Message différent si c'est l'utilisateur actuel
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
                
                db.session.commit()  # Sauvegarder les notifications
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

    # 🔥 AJOUT : Gestion de la méthode GET
    return render_template('share_youtube.html')
# --------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
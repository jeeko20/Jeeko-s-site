import os
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, session, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
import cloudinary
import cloudinary.uploader
from dotenv import load_dotenv


from datetime import datetime

def time_ago(dt):
    """Retourne une chaîne du type 'il y a 5 minutes', 'il y a 2 heures', etc."""
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
# --------------------
# Configuration de base
# --------------------
load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "fallback_secret_key")
app.permanent_session_lifetime = timedelta(days=7)
app.jinja_env.filters['time_ago'] = time_ago
# --------------------
# Database config
# --------------------
database_url = os.environ.get("DATABASE_URL")
if not database_url:
    raise RuntimeError("❌ DATABASE_URL introuvable !")
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# --------------------
# Cloudinary config
# --------------------
cloudinary.config(
    cloud_name=os.environ.get("CLOUDINARY_CLOUD_NAME"),
    api_key=os.environ.get("CLOUDINARY_API_KEY"),
    api_secret=os.environ.get("CLOUDINARY_API_SECRET")
)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS

def upload_avatar_to_cloudinary(file):
    try:
        result = cloudinary.uploader.upload(file)
        return result.get("secure_url")
    except Exception as e:
        logger.error(f"Erreur Cloudinary: {e}")
        flash("Échec de l'upload de l'image.", "danger")
        return None

# --------------------
# Modèles
# --------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    profile = db.relationship('Profile', backref='user', uselist=False)

class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    complete_name = db.Column(db.String(100))
    email = db.Column(db.String(150))
    bio = db.Column(db.Text)
    year_of_study = db.Column(db.String(50))
    avatar_path = db.Column(db.String(200))

class Ressource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    subject = db.Column(db.String(50), nullable=False)  # Matière
    file_url = db.Column(db.String(500), nullable=False)  # URL Cloudinary ou chemin
    file_type = db.Column(db.String(20), nullable=False)  # 'image', 'pdf', 'doc', etc.
    page_count = db.Column(db.Integer, default=0)  # Si PDF, nombre de pages
    likes = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relation pour accéder à l'utilisateur et son avatar
    user = db.relationship('User', backref=db.backref('ressources', lazy=True))

    @property
    def user_avatar(self):
        if self.user and self.user.profile:
            return self.user.profile.avatar_path
        return "https://via.placeholder.com/150"    

# --------------------
# Routes Flask
# --------------------
@app.before_request
def update_last_seen():
    """Met à jour last_seen à chaque requête pour les utilisateurs connectés"""
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            user.last_seen = datetime.utcnow()
            db.session.commit()

@app.route('/')
def home():
    username = session.get('username')
    return render_template('index.html', username=username)

@app.route('/api/stats')
def api_stats():
    total_users = User.query.count()
    # Considérer en ligne si last_seen < 5 minutes
    threshold = datetime.utcnow() - timedelta(minutes=5)
    active_users = User.query.filter(User.last_seen >= threshold).count()
    
    last_registered = [
        {"username": u.username, "email": u.email, "date": u.created_at.strftime("%Y-%m-%d %H:%M")}
        for u in User.query.order_by(User.created_at.desc()).limit(5)
    ]
    last_tasks = []  # ⚡ si tu as une table Task, ajoute ici
    return jsonify({
        "total_users": total_users,
        "active_users": active_users,
        "last_registered": last_registered,
        "total_tasks": len(last_tasks),
        "completed_tasks": sum(1 for t in last_tasks if t.get("completed")),
        "last_tasks": last_tasks
    })

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
            # Update last_seen au login
            user.last_seen = datetime.utcnow()
            db.session.commit()
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

import PyPDF2  # ⚠️ Installe avec: pip install PyPDF2
from io import BytesIO

from werkzeug.utils import secure_filename
from cloudinary.utils import cloudinary_url


@app.route('/share_ressource', methods=['POST'])
def share_ressource():
    if 'user_id' not in session:
        flash('Veuillez vous connecter pour partager une ressource.', 'warning')
        return redirect(url_for('communaute'))

    user_id = session['user_id']
    title = request.form.get('titre')
    subject = request.form.get('matiere')
    file = request.files.get('file')

    if not title or not subject or not file:
        flash('Tous les champs sont obligatoires.', 'danger')
        return redirect(url_for('communaute'))

    filename = secure_filename(file.filename)
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    allowed_types = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}
    if ext not in allowed_types:
        flash('Type de fichier non autorisé. Formats acceptés : png, jpg, jpeg, gif, pdf, doc, docx.', 'danger')
        return redirect(url_for('communaute'))

    # Détecter resource_type
    is_raw = ext in {'pdf', 'doc', 'docx'}
    resource_type = 'raw' if is_raw else 'image'

    # Lire nb pages si PDF (faire avant l'upload ou repositionner le stream)
    page_count = 0
    if ext == 'pdf':
        try:
            file.stream.seek(0)
            pdf_reader = PyPDF2.PdfReader(file.stream)
            page_count = len(pdf_reader.pages)
        except Exception as e:
            logger.warning(f"Impossible de lire localement le PDF: {e}")
            page_count = 0
        finally:
            file.stream.seek(0)  # remettre au début pour l'upload

    # Construire un public_id qui contient l'extension (important pour raw)
    public_id = filename  # secure_filename already contains the extension

    try:
        upload_result = cloudinary.uploader.upload(
            file,
            resource_type=resource_type,
            folder="edushare/ressources",
            public_id=public_id,      # <- important pour garder l'extension
            overwrite=True,
            invalidate=True,
            use_filename=False,       # on fournit public_id manuellement
            unique_filename=False,
            tags=["edushare"]
        )
        logger.info(f"🔁 upload_result keys: { {k: upload_result.get(k) for k in ['public_id','secure_url','resource_type','format']} }")

        # Générer une URL de téléchargement propre (fl_attachment)
        download_url, _ = cloudinary_url(
            upload_result.get('public_id'),
            resource_type=resource_type,
            flags='attachment',  # ajoute fl_attachment
            secure=True
        )

        file_url = download_url
        file_type = ext

    except Exception as e:
        logger.error(f"❌ Erreur upload Cloudinary : {e}")
        flash("Échec de l'upload du fichier.", "danger")
        return redirect(url_for('communaute'))

    # Sauvegarder en base
    new_ressource = Ressource(
        user_id=user_id,
        title=title,
        subject=subject,
        file_url=file_url,
        file_type=file_type,
        page_count=page_count
    )

    try:
        db.session.add(new_ressource)
        db.session.commit()
        flash('✅ Ressource partagée avec succès !', 'success')
        logger.info(f"🔗 URL du fichier : {file_url}")
    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ Erreur sauvegarde : {e}")
        flash("Erreur lors de la publication.", "danger")

    return redirect(url_for('communaute'))
 
@app.route('/notes')
def notes():
    return render_template('note.html')

@app.route('/communaute')
def communaute():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Récupérer les 10 dernières ressources
    ressources = Ressource.query.order_by(Ressource.created_at.desc()).limit(10).all()
    username = session.get('username')
    
    return render_template('communaute.html', username=username, ressources=ressources)

@app.route('/learn_html')
def learn_html():
    return render_template('learn_html.html')

@app.route('/learn_css')
def learn_css():
    return render_template('learn_css.html')

@app.route('/page_not_found')
def page_not_found():
    return render_template('page_not_found.html')

@app.route('/like_ressource/<int:ressource_id>', methods=['POST'])
def like_ressource(ressource_id):
    if 'user_id' not in session:
        return jsonify({"error": "Non connecté"}), 403

    ressource = Ressource.query.get(ressource_id)
    if not ressource:
        return jsonify({"error": "Ressource introuvable"}), 404

    ressource.likes += 1
    db.session.commit()

    return jsonify({"likes": ressource.likes}), 200
# --------------------
# Lancement Flask
# --------------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

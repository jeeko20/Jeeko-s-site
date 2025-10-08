import os
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
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

# -------------------- Configuration --------------------
load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "fallback_secret_key")
app.permanent_session_lifetime = timedelta(days=7)

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

def upload_avatar_to_cloudinary(file):
    try:
        result = cloudinary.uploader.upload(file)
        return result.get("secure_url")
    except Exception as e:
        logger.error(f"Erreur Cloudinary: {e}")
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

    @property
    def avatar_url(self):
        if self.profile and self.profile.avatar_path:
            return self.profile.avatar_path
        return "https://cdn.pixabay.com/photo/2024/06/22/22/55/man-8847064_640.jpg"

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

    # Relations
    user = db.relationship('User', backref=db.backref('saved_ressources', lazy=True))
    ressource = db.relationship('Ressource', backref=db.backref('saved_by', lazy=True))

    # Contrainte d'unicité : un utilisateur ne peut sauvegarder qu'une fois la même ressource
    __table_args__ = (db.UniqueConstraint('user_id', 'ressource_id', name='unique_user_ressource'),)

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
@login_required
def logout():
    logout_user()
    flash('Vous êtes déconnecté.', 'info')
    return redirect(url_for('home'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        complete_name = request.form['complete_name']
        email = request.form['email']
        bio = request.form['bio']
        year_of_study = request.form.get('year_of_study')
        avatar_file = request.files.get('avatar')
        avatar_path = current_user.profile.avatar_path if current_user.profile else None

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

        if current_user.profile:
            current_user.profile.complete_name = complete_name
            current_user.profile.email = email
            current_user.profile.bio = bio
            current_user.profile.year_of_study = year_of_study
            current_user.profile.avatar_path = avatar_path
        else:
            new_profile = Profile(
                complete_name=complete_name,
                email=email,
                bio=bio,
                year_of_study=year_of_study,
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


MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 Mo en octets

@app.route('/share_ressource', methods=['POST'])
@login_required
def share_ressource():
    title = request.form.get('titre')
    subject = request.form.get('matiere')
    files = request.files.getlist('files')  # Plusieurs fichiers

    if not title or not subject or not files:
        flash('Tous les champs sont obligatoires.', 'danger')
        return redirect(url_for('communaute'))

    # Filtrer les fichiers vides
    valid_files = [f for f in files if f and f.filename != '']
    if not valid_files:
        flash('Aucun fichier valide sélectionné.', 'danger')
        return redirect(url_for('communaute'))

    uploaded_count = 0

    for file in valid_files:
        filename = secure_filename(file.filename)
        if '.' not in filename:
            flash(f'Fichier invalide (pas d’extension) : {filename}', 'warning')
            continue

        ext = filename.rsplit('.', 1)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            flash(f'Type de fichier non autorisé : {ext} (fichier : {filename})', 'danger')
            continue

        # ✅ VÉRIFICATION DE LA TAILLE DU FICHIER (sécurité backend)
        try:
            # Obtenir la taille sans charger tout en mémoire
            file.seek(0, os.SEEK_END)
            file_size = file.tell()
            file.seek(0)  # Remettre le curseur au début pour l'upload

            if file_size > MAX_FILE_SIZE:
                flash(f"Fichier trop volumineux (max 100 Mo) : {filename}", "danger")
                continue
        except Exception as e:
            logger.error(f"Erreur lors de la vérification de la taille du fichier {filename}: {e}")
            flash(f"Erreur avec le fichier : {filename}", "danger")
            continue

        # Déterminer le type de ressource pour Cloudinary
        is_video = ext in {'mp4', 'mov', 'avi', 'mkv', 'webm'}
        is_document = ext in {'pdf', 'doc', 'docx'}
        resource_type = 'video' if is_video else ('raw' if is_document else 'image')

        # Compter les pages si PDF
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

        # Upload vers Cloudinary
        try:
            upload_result = cloudinary.uploader.upload(
                file,
                resource_type=resource_type,
                folder="edushare/ressources",
                public_id=filename,
                overwrite=True,
                invalidate=True,
                use_filename=False,
                unique_filename=True  # Évite les conflits de nom
            )

            # Générer les URLs
            if resource_type == "image":
                file_url = upload_result.get("secure_url")
                download_url, _ = cloudinary_url(
                    upload_result.get("public_id"),
                    resource_type="image",
                    flags="attachment",
                    secure=True
                )
            elif resource_type == "video":
                file_url = upload_result.get("secure_url")  # Pour balise <video>
                download_url = file_url  # Même URL pour téléchargement
            else:  # document (PDF, DOC, etc.)
                download_url, _ = cloudinary_url(
                    upload_result.get("public_id"),
                    resource_type="raw",
                    flags="attachment",
                    secure=True
                )
                file_url = download_url

        except Exception as e:
            logger.error(f"Erreur Cloudinary pour {filename}: {e}")
            flash(f"Échec de l'upload : {filename}", "danger")
            continue

        # Sauvegarder dans la base de données
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

    # Commit final
    try:
        db.session.commit()
        if uploaded_count > 0:
            flash(f'✅ {uploaded_count} ressource(s) partagée(s) avec succès !', 'success')
        else:
            flash('Aucune ressource n’a pu être partagée.', 'warning')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erreur lors de la sauvegarde en base : {e}")
        flash("Erreur critique lors de la publication.", "danger")

    return redirect(url_for('communaute'))
# -------------------- API --------------------
@app.route('/api/ressources')
@login_required
def api_ressources():
    ressources = Ressource.query.all()
    # Récupérer les IDs des ressources sauvegardées par l'utilisateur
    saved_ids = {sr.ressource_id for sr in SavedRessource.query.filter_by(user_id=current_user.id).all()}
    
    return jsonify([{
        "id": r.id,
        "title": r.title,
        "subject": r.subject,
        "file_type": r.file_type,
        "likes": r.likes,
        "created_at": r.created_at.isoformat(),
        "user_avatar": r.user_avatar,
        "username": r.user.username,
        "file_url": r.file_url,
        "download_url": r.download_url,
        "is_saved": r.id in saved_ids,  # ✅ Ajouté
        "is_video": r.file_type in ['mp4', 'mov', 'avi', 'mkv', 'webm']  # ✅ Pour l'affichage
    } for r in ressources])
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
    saved = SavedRessource.query.filter_by(user_id=current_user.id).all()
    return jsonify([{
        "id": s.ressource.id,
        "title": s.ressource.title,
        "subject": s.ressource.subject,
        "file_type": s.ressource.file_type,
        "created_at": s.ressource.created_at.isoformat(),
        "file_url": s.ressource.file_url,
        "download_url": s.ressource.download_url,
        "page_count": s.ressource.page_count,
        "user_avatar": s.ressource.user_avatar,
        "username": s.ressource.user.username,
        "is_video": s.ressource.file_type in ['mp4', 'mov', 'avi', 'mkv', 'webm']
    } for s in saved])
    
@app.route('/api/discussions', methods=['GET'])
def api_discussions():
    sort_by = request.args.get('sort', 'date')
    query = Discussion.query
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
        "user_avatar": d.user_avatar,
        "username": d.user.username,
        "comment_count": len(d.comments)
    } for d in discussions])

@app.route('/api/my_ressources')
@login_required
def api_my_ressources():
    # Récupérer toutes les ressources de l'utilisateur connecté
    ressources = Ressource.query.filter_by(user_id=current_user.id).order_by(Ressource.created_at.desc()).all()
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

@app.route('/api/discussion', methods=['POST'])
@login_required
def create_discussion():
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
        "user_avatar": new_discussion.user_avatar,
        "username": new_discussion.user.username,
        "comment_count": 0
    }), 201

@app.route('/api/discussion/<int:discussion_id>/comments', methods=['GET'])
def get_comments(discussion_id):
    comments = Comment.query.filter_by(discussion_id=discussion_id).order_by(Comment.created_at.asc()).all()
    return jsonify([{
        "id": c.id,
        "content": c.content,
        "created_at": c.created_at.isoformat(),
        "user_avatar": c.user_avatar,
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
        "user_avatar": new_comment.user_avatar,
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

# -------------------- Pages --------------------
@app.route('/communaute')
@login_required
def communaute():
    return render_template('communaute.html')

@app.route('/notes')
@login_required
def notes():
    return render_template('note.html')

@app.route('/learn_html')
def learn_html():
    return render_template('learn_html.html')

@app.route('/learn_css')
def learn_css():
    return render_template('learn_css.html')

@app.route('/page_not_found')
def page_not_found():
    return render_template('page_not_found.html')

@app.route('/systeme')
def systeme():
    return render_template('systeme.html')

# --------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
import os
import logging
import asyncio
import threading
from datetime import datetime, timedelta
from flask import Flask, render_template, request, session, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import cloudinary
import cloudinary.uploader
from telegram import Bot, Update, KeyboardButton, ReplyKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
import requests
from dotenv import load_dotenv
import pytz  # ✅ obligatoire pour apscheduler

# --------------------
# Configuration de base
# --------------------
load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "fallback_secret_key")
app.permanent_session_lifetime = timedelta(days=7)

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
    profile = db.relationship('Profile', backref='user', uselist=False)

class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    complete_name = db.Column(db.String(100))
    email = db.Column(db.String(150))
    bio = db.Column(db.Text)
    year_of_study = db.Column(db.String(50))
    avatar_path = db.Column(db.String(200))

# --------------------
# Telegram bot config
# --------------------
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
ADMIN_CHAT_ID = os.getenv("ADMIN_CHAT_ID")  # ton chat perso pour notifications
API_URL = os.getenv("API_URL")              # ton site API stats
API_TOKEN = os.getenv("API_SECRET_TOKEN")

bot = Bot(token=BOT_TOKEN)

def notify_admin(message: str):
    if ADMIN_CHAT_ID:
        bot.send_message(chat_id=ADMIN_CHAT_ID, text=message)

def get_main_menu():
    keyboard = [
        [KeyboardButton("📊 Voir les stats")],
        [KeyboardButton("👥 Derniers inscrits"), KeyboardButton("✅ Dernières tâches")],
        [KeyboardButton("ℹ️ Help")]
    ]
    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True, one_time_keyboard=False)

def fetch_stats():
    try:
        headers = {"X-API-TOKEN": API_TOKEN}
        response = requests.get(API_URL, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()
        return {"error": f"Erreur API : {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

# --------------------
# Bot handlers
# --------------------
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 Bienvenue sur le bot !",
        reply_markup=get_main_menu()
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "💡 *Fonctionnalités du bot :*\n\n"
        "📊 Voir les stats : Nombre d'utilisateurs et tâches\n"
        "👥 Derniers inscrits : Voir les utilisateurs récents\n"
        "✅ Dernières tâches : Voir les tâches récentes\n"
        "ℹ️ Help : Affiche ce menu\n"
    )
    await update.message.reply_text(msg, parse_mode="Markdown", reply_markup=get_main_menu())

async def handle_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text
    stats = fetch_stats()

    if text == "📊 Voir les stats":
        if "error" in stats:
            await update.message.reply_text(f"❌ {stats['error']}")
            return
        msg = (
            f"📈 *Statistiques*\n\n"
            f"👥 Utilisateurs inscrits : {stats.get('total_users',0)}\n"
            f"🟢 Utilisateurs actifs : {stats.get('active_users',0)}\n"
            f"📋 Tâches créées : {stats.get('total_tasks',0)}\n"
            f"✅ Tâches terminées : {stats.get('completed_tasks',0)}"
        )
        await update.message.reply_text(msg, parse_mode="Markdown", reply_markup=get_main_menu())

    elif text == "👥 Derniers inscrits":
        if "error" in stats or not stats.get("last_registered"):
            await update.message.reply_text("Aucun utilisateur récent.")
            return
        msg = "🆕 *Derniers inscrits :*\n"
        for u in stats["last_registered"]:
            msg += f"👤 {u['username']} ({u['email']}) - {u['date']}\n"
        await update.message.reply_text(msg, parse_mode="Markdown", reply_markup=get_main_menu())

    elif text == "✅ Dernières tâches":
        if "error" in stats or not stats.get("last_tasks"):
            await update.message.reply_text("Aucune tâche récente.")
            return
        msg = "📌 *Dernières tâches :*\n"
        for t in stats["last_tasks"]:
            status = "✅" if t["completed"] else "🕒"
            msg += f"{status} {t['title']} — @{t['user']} ({t['date']})\n"
        await update.message.reply_text(msg, parse_mode="Markdown", reply_markup=get_main_menu())

    elif text == "ℹ️ Help":
        await help_command(update, context)

def run_bot():
    # ⚡ Crée une boucle asyncio pour ce thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # ⚡ Crée l'application Telegram
    application = Application.builder().token(BOT_TOKEN).build()

    # ⚡ Force UTC pour JobQueue (évite l'erreur timezone)
    if application.job_queue:
        application.job_queue._scheduler.timezone = pytz.UTC

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_menu))

    print("🤖 Bot Telegram démarré...")
    loop.run_until_complete(application.run_polling())

# --------------------
# Routes Flask
# --------------------
@app.route('/')
def home():
    username = session.get('username')
    return render_template('index.html', username=username)

@app.route('/api/stats')
def api_stats():
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    last_registered = [
        {"username": u.username, "email": u.email, "date": u.created_at.strftime("%Y-%m-%d %H:%M")}
        for u in User.query.order_by(User.created_at.desc()).limit(5)
    ]
    last_tasks = []  # si tu as une table Task, remplis ici
    return jsonify({
        "total_users": total_users,
        "active_users": active_users,
        "last_registered": last_registered,
        "total_tasks": len(last_tasks),
        "completed_tasks": sum(1 for t in last_tasks if t.get("completed")),
        "last_tasks": last_tasks
    })
# --------------------
# Exemple route login/register avec notification
# --------------------
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


@app.route('/notes')
def notes():
    return render_template('note.html')

@app.route('/communaute')
def communaute():
    return render_template('communaute.html')

@app.route('/learn_html')
def learn_html():
    return render_template('learn_html.html')

@app.route('/learn_css')
def learn_css():
    return render_template('learn_css.html')

# --------------------
# Lancement Flask + Bot
# --------------------
if __name__ == "__main__":
    threading.Thread(target=run_bot, daemon=True).start()
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

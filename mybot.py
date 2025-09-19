import os
import asyncio
import requests
from telegram import Bot, Update, KeyboardButton, ReplyKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from dotenv import load_dotenv

# --------------------
# Charger le .env
# --------------------
load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
API_TOKEN = os.getenv("API_TOKEN")        # ✅ correspond à ton .env
ADMIN_CHAT_ID = os.getenv("ADMIN_CHAT_ID")
API_URL = os.getenv("API_URL")

bot = Bot(token=BOT_TOKEN)

# --------------------
# Menu principal du bot
# --------------------
def get_main_menu():
    keyboard = [
        [KeyboardButton("📊 Voir les stats")],
        [KeyboardButton("👥 Derniers inscrits"), KeyboardButton("✅ Dernières tâches")],
        [KeyboardButton("ℹ️ Help")]
    ]
    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True, one_time_keyboard=False)

# --------------------
# Fonction pour récupérer les stats depuis l'API
# --------------------
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
# Handlers du bot
# --------------------
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("👋 Bienvenue sur le bot !", reply_markup=get_main_menu())

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "💡 *Fonctionnalités du bot :*\n\n"
        "📊 Voir les stats\n"
        "👥 Derniers inscrits\n"
        "✅ Dernières tâches\n"
        "ℹ️ Help"
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
            f"📈 Statistiques :\n"
            f"👥 Utilisateurs inscrits : {stats.get('total_users',0)}\n"
            f"🟢 Utilisateurs actifs : {stats.get('active_users',0)}\n"
            f"📋 Tâches créées : {stats.get('total_tasks',0)}\n"
            f"✅ Tâches terminées : {stats.get('completed_tasks',0)}"
        )
        await update.message.reply_text(msg, reply_markup=get_main_menu())

    elif text == "👥 Derniers inscrits":
        last_users = stats.get("last_registered", [])
        if not last_users:
            await update.message.reply_text("Aucun utilisateur récent.")
            return
        msg = "🆕 Derniers inscrits :\n"
        for u in last_users:
            msg += f"👤 {u['username']} ({u['email']}) - {u['date']}\n"
        await update.message.reply_text(msg, reply_markup=get_main_menu())

    elif text == "✅ Dernières tâches":
        last_tasks = stats.get("last_tasks", [])
        if not last_tasks:
            await update.message.reply_text("Aucune tâche récente.")
            return
        msg = "📌 Dernières tâches :\n"
        for t in last_tasks:
            status = "✅" if t.get("completed") else "🕒"
            msg += f"{status} {t['title']} — @{t['user']} ({t['date']})\n"
        await update.message.reply_text(msg, reply_markup=get_main_menu())

    elif text == "ℹ️ Help":
        await help_command(update, context)
    else:
        await update.message.reply_text(f"Fonctionnalité '{text}' en dev.", reply_markup=get_main_menu())

# --------------------
# Lancement du bot
# --------------------
def main():
    application = Application.builder().token(BOT_TOKEN).build()

    # Ajouter les handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_menu))

    print("🤖 Bot Telegram démarré en polling...")
    application.run_polling()

# --------------------
# Script principal
# --------------------
if __name__ == "__main__":
    print(f"BOT_TOKEN = {BOT_TOKEN}")
    print(f"API_TOKEN = {API_TOKEN}")
    print(f"ADMIN_CHAT_ID = {ADMIN_CHAT_ID}")
    print(f"API_URL = {API_URL}")
    main()

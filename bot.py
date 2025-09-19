import os
import asyncio
import requests
from telegram import Bot, Update, KeyboardButton, ReplyKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
import pytz

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
ADMIN_CHAT_ID = os.getenv("ADMIN_CHAT_ID")
API_URL = os.getenv("API_URL")
API_TOKEN = os.getenv("API_SECRET_TOKEN")

bot = Bot(token=BOT_TOKEN)

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
    await update.message.reply_text(f"Fonctionnalité '{text}' en dev (stats simulées)")

def main():
    application = Application.builder().token(BOT_TOKEN).build()
    application.job_queue._scheduler.timezone = pytz.UTC
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_menu))
    print("🤖 Bot Telegram démarré en polling...")
    application.run_polling()

if __name__ == "__main__":
    main()

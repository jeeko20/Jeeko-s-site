import os
import requests
import json
import logging

logger = logging.getLogger(__name__)

# Charger .env automatiquement si python-dotenv est installé (optionnel)
try:
    from dotenv import load_dotenv
    # Cherche un fichier .env à la racine du projet
    project_root = os.path.dirname(os.path.abspath(__file__))
    # remonte d'un niveau si le fichier notifications.py se trouve dans un package
    possible_env = os.path.join(project_root, '..', '.env')
    load_dotenv()  # simple call: permet la lecture si .env est dans le cwd ou parent
    # Si vous préférez, on peut appeler load_dotenv(possible_env)
    logger.debug("python-dotenv trouvé : .env chargé (si présent)")
except Exception:
    # dotenv n'est pas installé, ce n'est pas bloquant — on utilise os.environ
    logger.debug("python-dotenv non trouvé : lecture directe des variables d'environnement")

# Lire la config depuis l'environnement (préférable pour la sécurité)
GREEN_API_URL = os.getenv(
    "GREEN_API_URL",
)

# Chat ID par défaut (groupe). Configurez GREEN_CHAT_ID dans .env pour le remplacer.
GREEN_CHAT_ID = os.getenv("GREEN_CHAT_ID")


def send_whatsapp_notification(message, title: str = None, link: str = None) -> bool:
    """Envoie une notification WhatsApp via Green API.

    - message: texte principal (plain text).
    - title: titre affiché dans customPreview (optionnel).
    - link: URL vers la ressource (optionnel). Le lien est ajouté au message pour être cliquable.
    """
    payload_message = message
    if link:
        # Ajouter le lien sur une nouvelle ligne pour être bien visible
        payload_message = f"{message}\n\nAccéder: {link}"

    payload = {
        "chatId": GREEN_CHAT_ID,
        "message": payload_message,
        "customPreview": {
            "title": title or "Nouveau message"
        }
    }

    headers = {"Content-Type": "application/json"}

    try:
        logger.info(f"Envoi notification WhatsApp — titre={title!r} link={link!r}")
        logger.debug(f"Payload: {payload}")
        response = requests.post(GREEN_API_URL, json=payload, headers=headers, timeout=10)
        response.raise_for_status()
        logger.info(f"Notification envoyée, réponse API: {response.text}")
        return True
    except Exception as e:
        logger.error(f"Erreur lors de l'envoi de la notification WhatsApp: {e}")
        try:
            logger.debug(f"Réponse brute (si présente): {response.text}")
        except Exception:
            pass
        logger.debug(f"Payload erreur: {payload}")
        return False


def notify_new_quiz(quiz_title, author, link: str = None):
    """Envoie une notification pour un nouveau quiz, avec lien optionnel."""
    message = f"📝 Nouveau Quiz ajouté!\n\n📌 Titre: {quiz_title}\n👤 Auteur: {author}\n🎯 Testez vos connaissances maintenant!"
    return send_whatsapp_notification(message, title="Nouveau Quiz", link=link)


def notify_new_flashcard(flashcard_title, author, link: str = None):
    """Envoie une notification pour une nouvelle flashcard, avec lien optionnel."""
    message = f"🎴 Nouvelle Flashcard créée!\n\n📌 Titre: {flashcard_title}\n👤 Auteur: {author}\n🧠 Commencez à réviser!"
    return send_whatsapp_notification(message, title="Nouv. Flashcard", link=link)


def notify_new_file(filename, author, file_type, link: str = None):
    """Envoie une notification pour un nouveau fichier, avec lien optionnel."""
    icons = {
        "pdf": "📄",
        "doc": "📝",
        "docx": "📝",
        "jpg": "🖼️",
        "jpeg": "🖼️",
        "png": "🖼️",
        "gif": "🎨",
        "mp4": "🎥",
        "mov": "🎥",
        "avi": "🎥",
        "mkv": "🎥",
        "webm": "🎥",
    }

    file_icon = icons.get((file_type or "").lower(), "📎")
    message = f"{file_icon} Nouveau fichier partagé sur Univloop.site!\n\n📌 Nom: {filename}\n👤 Partagé par: {author}\n💫 Accédez-y maintenant!"
    return send_whatsapp_notification(message, title="Nouvelle ressource", link=link)
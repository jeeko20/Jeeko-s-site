import requests
import json
import logging

logger = logging.getLogger(__name__)

GREEN_API_URL = "https://7107.api.green-api.com/waInstance7107370344/sendMessage/64dc490fc0774c5596b2a92d009c75666faab85f5d5d4f86a2"


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
        "chatId": "120363422109468267@g.us",
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
from functools import wraps
from flask import session, redirect, url_for, flash, current_app, request
from supabase import create_client, Client
from supabase.lib.client_options import ClientOptions
import os
from dotenv import load_dotenv
from urllib.parse import urlparse, urljoin

load_dotenv()

# Configuration Supabase
SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY')

# Configuration du client Supabase avec des options personnalisées
client_options = ClientOptions(
    postgrest_client_timeout=10,  # Timeout en secondes
    auto_refresh_token=True,
    persist_session=True
)

# Création du client Supabase
supabase: Client = create_client(
    SUPABASE_URL,
    SUPABASE_KEY,
    options=client_options
)

def is_safe_url(target):
    """Vérifie si l'URL est sûre pour la redirection"""
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

def login_required(f):
    """Décorateur pour les routes qui nécessitent une authentification"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_authenticated():
            flash('Veuillez vous connecter pour accéder à cette page', 'warning')
            return redirect(url_for('auth.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    """Récupère les informations de l'utilisateur connecté"""
    if 'user' not in session:
        # Essayer de rafraîchir la session si possible
        if 'refresh_token' in session:
            try:
                response = supabase.auth.refresh_session(session['refresh_token'])
                if response.user:
                    session['user'] = {
                        'id': response.user.id,
                        'email': response.user.email,
                        'user_metadata': response.user.user_metadata or {}
                    }
                    session['access_token'] = response.session.access_token
                    session['refresh_token'] = response.session.refresh_token
            except Exception as e:
                # En cas d'erreur, on déconnecte l'utilisateur
                logout_user()
                return None
    return session.get('user')

def is_authenticated():
    """Vérifie si l'utilisateur est authentifié"""
    # Vérifier si le token est toujours valide
    if 'access_token' in session:
        try:
            # Vérifier si le token est expiré
            supabase.auth.get_user(session['access_token'])
            return True
        except Exception:
            # Essayer de rafraîchir le token
            if 'refresh_token' in session:
                try:
                    response = supabase.auth.refresh_session(session['refresh_token'])
                    if response.user:
                        session['user'] = {
                            'id': response.user.id,
                            'email': response.user.email,
                            'user_metadata': response.user.user_metadata or {}
                        }
                        session['access_token'] = response.session.access_token
                        session['refresh_token'] = response.session.refresh_token
                        return True
                except Exception:
                    pass
            # Si le rafraîchissement échoue, on déconnecte l'utilisateur
            logout_user()
    return False

def login_user(email, password, remember=False):
    """
    Authentifie un utilisateur avec email/mot de passe
    
    Args:
        email (str): Email de l'utilisateur
        password (str): Mot de passe de l'utilisateur
        remember (bool): Si True, la session sera maintenue plus longtemps
        
    Returns:
        tuple: (success: bool, message: str)
    """
    try:
        response = supabase.auth.sign_in_with_password({
            "email": email,
            "password": password
        })
        
        if response.user:
            # Stocker les informations utilisateur essentielles en session
            session['user'] = {
                'id': response.user.id,
                'email': response.user.email,
                'user_metadata': response.user.user_metadata or {}
            }
            
            # Stocker les tokens
            session['access_token'] = response.session.access_token
            session['refresh_token'] = response.session.refresh_token
            
            # Configurer la durée de la session
            session.permanent = remember
            
            return True, None
            
    except Exception as e:
        error_msg = str(e)
        if "Invalid login credentials" in error_msg:
            return False, "Email ou mot de passe incorrect"
        elif "Email not confirmed" in error_msg:
            return False, "Veuvez confirmer votre email avant de vous connecter"
        else:
            current_app.logger.error(f"Erreur de connexion: {error_msg}")
            return False, "Une erreur est survenue lors de la connexion"
    
    return False, "Échec de l'authentification"

def register_user(email, password, user_data=None):
    """
    Inscrit un nouvel utilisateur
    
    Args:
        email (str): Email de l'utilisateur
        password (str): Mot de passe de l'utilisateur
        user_data (dict, optional): Données supplémentaires pour le profil utilisateur
        
    Returns:
        tuple: (success: bool, message: str)
    """
    try:
        # Inscription de l'utilisateur avec Supabase Auth
        response = supabase.auth.sign_up({
            "email": email,
            "password": password,
            "options": {
                "data": user_data or {}
            }
        })
        
        if response.user:
            # Le profil est automatiquement créé par le trigger PostgreSQL
            return True, "Un email de confirmation a été envoyé. Veuillez vérifier votre boîte mail."
            
    except Exception as e:
        error_msg = str(e)
        if "User already registered" in error_msg:
            return False, "Un compte existe déjà avec cette adresse email"
        elif "Password should be at least" in error_msg:
            return False, "Le mot de passe doit contenir au moins 6 caractères"
        else:
            current_app.logger.error(f"Erreur d'inscription: {error_msg}")
            return False, "Une erreur est survenue lors de l'inscription"
    
    return False, "Échec de l'inscription"

def logout_user():
    """
    Déconnecte l'utilisateur et nettoie la session
    """
    try:
        # Déconnexion côté Supabase
        if 'access_token' in session:
            supabase.auth.sign_out(session['access_token'])
    except Exception as e:
        current_app.logger.error(f"Erreur lors de la déconnexion: {str(e)}")
    finally:
        # Nettoyage de la session
        session_keys = ['user', 'access_token', 'refresh_token']
        for key in session_keys:
            session.pop(key, None)
        
        # Régénérer le cookie de session pour éviter les attaques de fixation de session
        session.clear()
        session.regenerate()

def reset_password(email):
    """
    Envoie un email de réinitialisation de mot de passe
    
    Args:
        email (str): Email de l'utilisateur
        
    Returns:
        tuple: (success: bool, message: str)
    """
    try:
        # URL de redirection après réinitialisation (à personnaliser selon vos besoins)
        redirect_to = f"{request.host_url}auth/update-password"
        
        supabase.auth.reset_password_for_email(email, {
            "redirect_to": redirect_to
        })
        
        # Pour des raisons de sécurité, on ne précise pas si l'email existe ou non
        return True, "Si votre adresse email existe dans notre système, vous recevrez un lien de réinitialisation."
        
    except Exception as e:
        error_msg = str(e)
        current_app.logger.error(f"Erreur de réinitialisation de mot de passe: {error_msg}")
        return False, "Une erreur est survenue lors de l'envoi de l'email de réinitialisation"

def update_password(new_password):
    """
    Met à jour le mot de passe de l'utilisateur connecté
    
    Args:
        new_password (str): Nouveau mot de passe
        
    Returns:
        tuple: (success: bool, message: str)
    """
    try:
        if 'access_token' not in session:
            return False, "Non autorisé"
            
        response = supabase.auth.update_user({
            "password": new_password
        })
        
        if response.user:
            return True, "Votre mot de passe a été mis à jour avec succès"
            
    except Exception as e:
        error_msg = str(e)
        current_app.logger.error(f"Erreur de mise à jour du mot de passe: {error_msg}")
        return False, "Une erreur est survenue lors de la mise à jour de votre mot de passe"
    
    return False, "Échec de la mise à jour du mot de passe"

def get_user_profile(user_id=None):
    """
    Récupère le profil utilisateur depuis la table profiles
    
    Args:
        user_id (str, optional): ID de l'utilisateur. Si None, utilise l'utilisateur connecté
        
    Returns:
        dict or None: Les données du profil ou None si non trouvé
    """
    if user_id is None:
        if 'user' not in session:
            return None
        user_id = session['user']['id']
    
    try:
        response = supabase.table('profiles').select('*').eq('id', user_id).execute()
        if response.data and len(response.data) > 0:
            return response.data[0]
    except Exception as e:
        current_app.logger.error(f"Erreur lors de la récupération du profil: {str(e)}")
    
    return None

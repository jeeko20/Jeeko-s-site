from flask import Blueprint, redirect, url_for, session, request, flash, render_template, current_app
from auth_utils import (
    login_user, register_user, logout_user, 
    reset_password, update_password, is_safe_url,
    get_user_profile
)
from functools import wraps

# Création du Blueprint d'authentification
auth_bp = Blueprint('auth', __name__, template_folder='templates')

def handle_auth_errors(f):
    """Décorateur pour gérer les erreurs d'authentification"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            current_app.logger.error(f"Erreur d'authentification: {str(e)}")
            flash("Une erreur est survenue. Veuillez réessayer.", "error")
            return redirect(url_for('home'))
    return decorated_function

@auth_bp.route('/login', methods=['GET', 'POST'])
@handle_auth_errors
def login():
    # Si l'utilisateur est déjà connecté, on le redirige
    if 'user' in session:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'
        
        success, message = login_user(email, password, remember)
        
        if success:
            flash('Connexion réussie!', 'success')
            
            # Redirection sécurisée
            next_page = request.args.get('next')
            if not next_page or not is_safe_url(next_page):
                next_page = url_for('home')
                
            return redirect(next_page)
        else:
            flash(message or 'Échec de la connexion', 'error')
    
    # Pré-remplir l'email si présent dans la requête
    email = request.args.get('email', '')
    return render_template('auth/login.html', email=email)

@auth_bp.route('/register', methods=['GET', 'POST'])
@handle_auth_errors
def register():
    # Si l'utilisateur est déjà connecté, on le redirige
    if 'user' in session:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        full_name = request.form.get('full_name', '').strip()
        
        # Validation des données
        if not all([email, password, confirm_password]):
            flash('Tous les champs sont obligatoires', 'error')
            return render_template('auth/register.html', 
                                email=email, 
                                full_name=full_name)
        
        if password != confirm_password:
            flash('Les mots de passe ne correspondent pas', 'error')
            return render_template('auth/register.html', 
                                email=email, 
                                full_name=full_name)
        
        # Données supplémentaires pour le profil utilisateur
        user_data = {
            'full_name': full_name,
            # Ajoutez d'autres champs personnalisés ici si nécessaire
        }
        
        # Inscription de l'utilisateur
        success, message = register_user(email, password, user_data)
        
        if success:
            flash(message or 'Inscription réussie! Veuillez vérifier votre email pour confirmer votre compte.', 'success')
            return redirect(url_for('auth.login', email=email))
        else:
            flash(message or "Une erreur est survenue lors de l'inscription.", 'error')
    
    # Afficher le formulaire d'inscription
    email = request.args.get('email', '')
    return render_template('auth/register.html', email=email)

@auth_bp.route('/logout')
@handle_auth_errors
def logout():
    logout_user()
    flash('Vous avez été déconnecté avec succès.', 'info')
    return redirect(url_for('home'))

@auth_bp.route('/reset-password', methods=['GET', 'POST'])
@handle_auth_errors
def reset_password_request():
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash('Veuvez fournir une adresse email', 'error')
            return render_template('auth/reset_password.html')
        
        success, message = reset_password(email)
        flash(message, 'success' if success else 'error')
        
        if success:
            return redirect(url_for('auth.login'))
    
    return render_template('auth/reset_password.html')

@auth_bp.route('/update-password', methods=['GET', 'POST'])
@handle_auth_errors
def update_password_request():
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([password, confirm_password]):
            flash('Tous les champs sont obligatoires', 'error')
            return render_template('auth/update_password.html')
        
        if password != confirm_password:
            flash('Les mots de passe ne correspondent pas', 'error')
            return render_template('auth/update_password.html')
        
        success, message = update_password(password)
        
        if success:
            flash(message or 'Mot de passe mis à jour avec succès.', 'success')
            return redirect(url_for('home'))
        else:
            flash(message or "Une erreur est survenue lors de la mise à jour du mot de passe.", 'error')
    
    return render_template('auth/update_password.html')

// Gestion de la session utilisateur
window.CURRENT_USER_ID = null;

// Fonction pour mettre à jour l'interface utilisateur en fonction de l'état de connexion
function updateUIBasedOnAuth() {
    const loginButtons = document.querySelectorAll('.btn-login');
    const logoutButtons = document.querySelectorAll('.btn-logout');
    const userMenu = document.getElementById('user-menu');
    
    if (window.CURRENT_USER_ID) {
        // Utilisateur connecté
        loginButtons.forEach(btn => btn.style.display = 'none');
        logoutButtons.forEach(btn => btn.style.display = 'block');
        if (userMenu) userMenu.style.display = 'block';
    } else {
        // Utilisateur non connecté
        loginButtons.forEach(btn => btn.style.display = 'block');
        logoutButtons.forEach(btn => btn.style.display = 'none');
        if (userMenu) userMenu.style.display = 'none';
    }
}

// Appel initial de la fonction de mise à jour de l'interface
document.addEventListener('DOMContentLoaded', updateUIBasedOnAuth);

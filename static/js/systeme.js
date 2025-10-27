// Navigation SPA pour Systèmes d'Exploitation
class SystemeNavigation {
    constructor() {
        this.sections = document.querySelectorAll('.systeme-section');
        this.navLinks = document.querySelectorAll('.nav-link');
        this.currentSection = 'windows';
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.setupScrollTop();
        this.showSection(this.currentSection);
    }

    setupEventListeners() {
        // Navigation par clic
        this.navLinks.forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const sectionId = link.getAttribute('data-section');
                this.navigateToSection(sectionId);
            });
        });

        // Navigation par hash URL
        window.addEventListener('hashchange', () => {
            const sectionId = window.location.hash.substring(1) || 'windows';
            this.navigateToSection(sectionId);
        });

        // Navigation initiale
        const initialSection = window.location.hash.substring(1) || 'windows';
        this.navigateToSection(initialSection);
    }

    navigateToSection(sectionId) {
        // Mettre à jour l'URL sans recharger la page
        history.replaceState(null, null, `#${sectionId}`);
        
        // Changer de section
        this.showSection(sectionId);
        
        // Mettre à jour la navigation active
        this.updateActiveNav(sectionId);
        
        // Scroll vers le haut de la section
        this.scrollToSection(sectionId);
    }

    showSection(sectionId) {
        // Cacher toutes les sections
        this.sections.forEach(section => {
            section.classList.remove('active');
        });

        // Afficher la section active
        const activeSection = document.getElementById(sectionId);
        if (activeSection) {
            activeSection.classList.add('active');
            this.currentSection = sectionId;
        }
    }

    updateActiveNav(sectionId) {
        this.navLinks.forEach(link => {
            link.classList.remove('active');
            if (link.getAttribute('data-section') === sectionId) {
                link.classList.add('active');
            }
        });
    }

    scrollToSection(sectionId) {
        const section = document.getElementById(sectionId);
        if (section) {
            const navHeight = document.querySelector('.systeme-nav').offsetHeight;
            const offsetTop = section.offsetTop - navHeight - 20;
            
            window.scrollTo({
                top: offsetTop,
                behavior: 'smooth'
            });
        }
    }

    setupScrollTop() {
        const scrollTopBtn = document.getElementById('scrollTop');
        
        scrollTopBtn.addEventListener('click', () => {
            window.scrollTo({
                top: 0,
                behavior: 'smooth'
            });
        });

        window.addEventListener('scroll', () => {
            if (window.pageYOffset > 300) {
                scrollTopBtn.style.display = 'block';
            } else {
                scrollTopBtn.style.display = 'none';
            }
        });
    }
}

// Initialisation quand la page est chargée
document.addEventListener('DOMContentLoaded', () => {
    new SystemeNavigation();
});

// Effets d'animation supplémentaires
document.addEventListener('DOMContentLoaded', function() {
    // Animation des cartes au scroll
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, observerOptions);

    // Observer les cartes dans la section active
    function observeActiveSection() {
        const activeSection = document.querySelector('.systeme-section.active');
        if (activeSection) {
            const cards = activeSection.querySelectorAll('.content-card, .distro-card, .astuce-card, .ressource-card');
            cards.forEach(card => {
                card.style.opacity = '0';
                card.style.transform = 'translateY(20px)';
                card.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
                observer.observe(card);
            });
        }
    }

    // Réobserver quand on change de section
    const navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(link => {
        link.addEventListener('click', () => {
            setTimeout(observeActiveSection, 300);
        });
    });

    // Observer initial
    observeActiveSection();
});
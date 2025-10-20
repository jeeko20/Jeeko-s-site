// Configuration
let allQuizzes = [];
let currentQuiz = null;
let currentAttempt = [];
let currentQuestionIndex = 0;
let isSubmitting = false;

// Chargement des quiz
async function loadQuizzes() {
    try {
        const response = await fetch('/api/quizzes');
        allQuizzes = await response.json();
        renderQuizzes(allQuizzes);
        updateQuizStats();
    } catch (error) {
        console.error('Erreur chargement quiz:', error);
        showToast('Erreur lors du chargement des quiz', 'error');
    }
}

function renderQuizzes(quizzes) {
    const container = document.getElementById('quizzes-container');
    
    if (quizzes.length === 0) {
        container.innerHTML = `
            <div class="empty-state" style="grid-column: 1 / -1;">
                <i class="fas fa-brain"></i>
                <h3>Aucun quiz disponible</h3>
                <p>Soyez le premier à créer un quiz pour votre classe !</p>
                <button class="btn btn-primary" onclick="openCreateQuizModal()" style="margin-top: 20px;">
                    <i class="fas fa-plus"></i> Créer le premier quiz
                </button>
            </div>
        `;
        return;
    }

    container.innerHTML = quizzes.map(quiz => `
        <div class="quiz-card">
            <div class="quiz-header-mini">
                <img src="${quiz.user_avatar}" alt="Avatar" class="quiz-avatar"
                     onerror="this.src='https://cdn.pixabay.com/photo/2024/06/22/22/55/man-8847064_640.jpg'">
                <div class="quiz-title-section">
                    <h3 class="quiz-title">${quiz.title}</h3>
                    <div class="quiz-meta">
                        <span>par ${quiz.username}</span>
                        <span>${new Date(quiz.created_at).toLocaleDateString('fr-FR')}</span>
                    </div>
                </div>
            </div>
            
            <div class="quiz-meta">
                <span class="quiz-subject">${quiz.subject}</span>
                <span>${quiz.questions_count} question${quiz.questions_count > 1 ? 's' : ''}</span>
            </div>
            
            <p class="quiz-description">${quiz.description || 'Aucune description'}</p>
            
            <div class="quiz-stats">
                <div class="stat">
                    <i class="fas fa-users"></i>
                    <span>${quiz.attempts_count} tentative${quiz.attempts_count > 1 ? 's' : ''}</span>
                </div>
                <div class="stat">
                    <i class="fas fa-history"></i>
                    <span>${quiz.my_attempts} fois passé</span>
                </div>
            </div>
            
            <div class="quiz-actions">
                <button class="btn-quiz btn-start" onclick="startQuiz(${quiz.id})">
                    <i class="fas fa-play"></i> Commencer
                </button>
                ${quiz.my_attempts > 0 ? `
                    <button class="btn-quiz btn-results" onclick="showQuizResults(${quiz.id})">
                        <i class="fas fa-chart-bar"></i> Résultats
                    </button>
                ` : ''}
            </div>
        </div>
    `).join('');
}

function updateQuizStats() {
    document.getElementById('total-quizzes').textContent = allQuizzes.length;
    
    const totalAttempts = allQuizzes.reduce((sum, quiz) => sum + quiz.my_attempts, 0);
    document.getElementById('my-attempts').textContent = totalAttempts;
    
    const totalQuestions = allQuizzes.reduce((sum, quiz) => sum + quiz.questions_count, 0);
    document.getElementById('total-questions').textContent = totalQuestions;
}

// Gestion des modaux
function openCreateQuizModal() {
    document.getElementById('create-quiz-modal').style.display = 'flex';
    // Réinitialiser le formulaire
    document.getElementById('quiz-title').value = '';
    document.getElementById('quiz-subject-select').value = '';
    document.getElementById('quiz-description').value = '';
    document.getElementById('questions-grid').innerHTML = '';
    addQuestion(); // Ajouter une question par défaut
}

function closeCreateQuizModal() {
    document.getElementById('create-quiz-modal').style.display = 'none';
}

function closeQuizModal() {
    document.getElementById('quiz-modal').style.display = 'none';
    currentQuiz = null;
    currentAttempt = [];
    currentQuestionIndex = 0;
}

function closeResultsModal() {
    document.getElementById('results-modal').style.display = 'none';
}

// Gestion des questions
function addQuestion() {
    const questionsGrid = document.getElementById('questions-grid');
    const questionIndex = questionsGrid.children.length;
    
    const questionHTML = `
        <div class="question-item-expanded new" data-index="${questionIndex}">
            <div class="question-header-expanded">
                <span class="question-number-expanded">Question ${questionIndex + 1}</span>
                <div class="question-actions">
                    <button type="button" class="btn-icon" onclick="moveQuestionUp(${questionIndex})" 
                            ${questionIndex === 0 ? 'disabled style="opacity: 0.5;"' : ''}
                            title="Déplacer vers le haut">
                        <i class="fas fa-arrow-up"></i>
                    </button>
                    <button type="button" class="btn-icon" onclick="moveQuestionDown(${questionIndex})"
                            title="Déplacer vers le bas">
                        <i class="fas fa-arrow-down"></i>
                    </button>
                    <button type="button" class="btn-icon btn-remove-question" onclick="removeQuestion(${questionIndex})"
                            title="Supprimer la question">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </div>
            
            <textarea class="question-input-expanded" 
                      placeholder="Entrez votre question ici..." 
                      required></textarea>
            
            <div class="answers-section">
                <div class="answers-title" style="margin-bottom: 15px;">
                    <i class="fas fa-list-ol"></i>
                    Réponses (cochez la bonne réponse)
                </div>
                <div class="answers-grid-expanded" id="answers-${questionIndex}">
                    <!-- Réponses seront ajoutées ici -->
                </div>
                
                <div style="display: flex; gap: 12px; margin-top: 15px;">
                    <button type="button" class="btn-secondary-large" onclick="addAnswer(${questionIndex})" style="flex: 1;">
                        <i class="fas fa-plus"></i>
                        Ajouter une réponse
                    </button>
                    <button type="button" class="btn-remove-answer" onclick="removeLastAnswer(${questionIndex})"
                            style="padding: 12px 20px;"
                            title="Supprimer la dernière réponse">
                        <i class="fas fa-minus"></i>
                    </button>
                </div>
            </div>
        </div>
    `;
    
    questionsGrid.insertAdjacentHTML('beforeend', questionHTML);
    
    // Ajouter 4 réponses par défaut
    for (let i = 0; i < 4; i++) {
        addAnswer(questionIndex);
    }
    
    // Mettre à jour le compteur
    updateQuestionCounter();
    
    // Supprimer l'animation après un moment
    setTimeout(() => {
        const newQuestion = questionsGrid.lastElementChild;
        if (newQuestion) {
            newQuestion.classList.remove('new');
        }
    }, 300);
}

function addAnswer(questionIndex) {
    const answersList = document.getElementById(`answers-${questionIndex}`);
    if (!answersList) return;
    
    const answerCount = answersList.children.length;
    
    const answerHTML = `
        <div class="answer-item-expanded" data-answer-index="${answerCount}">
            <input type="radio" name="correct-${questionIndex}" value="${answerCount}" 
                   class="answer-radio" ${answerCount === 0 ? 'checked' : ''}
                   onchange="markCorrectAnswer(this, ${questionIndex})">
            <textarea class="answer-input-expanded" 
                      placeholder="Entrez la réponse..." 
                      required></textarea>
            <button type="button" class="btn-remove-answer" onclick="removeAnswer(this, ${questionIndex})">
                <i class="fas fa-times"></i>
            </button>
        </div>
    `;
    
    answersList.insertAdjacentHTML('beforeend', answerHTML);
    
    // Marquer la première réponse comme correcte par défaut
    if (answerCount === 0) {
        markCorrectAnswer(answersList.querySelector('.answer-radio'), questionIndex);
    }
}

function markCorrectAnswer(radioElement, questionIndex) {
    const answerItem = radioElement.closest('.answer-item-expanded');
    const allAnswers = document.querySelectorAll(`#answers-${questionIndex} .answer-item-expanded`);
    
    allAnswers.forEach(item => item.classList.remove('correct'));
    answerItem.classList.add('correct');
}

function removeAnswer(button, questionIndex) {
    const answersList = document.getElementById(`answers-${questionIndex}`);
    const answerItems = answersList.querySelectorAll('.answer-item-expanded');
    
    if (answerItems.length > 2) {
        const answerItem = button.closest('.answer-item-expanded');
        const isCorrect = answerItem.classList.contains('correct');
        
        answerItem.remove();
        
        // Si on supprime la réponse correcte, marquer la première comme correcte
        if (isCorrect && answerItems.length > 1) {
            const firstRadio = answersList.querySelector('.answer-radio');
            if (firstRadio) {
                firstRadio.checked = true;
                markCorrectAnswer(firstRadio, questionIndex);
            }
        }
        
        updateAnswerIndexes(questionIndex);
    } else {
        showToast('Une question doit avoir au moins 2 réponses', 'warning');
    }
}

function removeLastAnswer(questionIndex) {
    const answersList = document.getElementById(`answers-${questionIndex}`);
    const answerItems = answersList.querySelectorAll('.answer-item-expanded');
    
    if (answerItems.length > 2) {
        answerItems[answerItems.length - 1].remove();
        updateAnswerIndexes(questionIndex);
    } else {
        showToast('Une question doit avoir au moins 2 réponses', 'warning');
    }
}

function removeQuestion(index) {
    const questionsGrid = document.getElementById('questions-grid');
    const questionElements = questionsGrid.querySelectorAll('.question-item-expanded');
    
    if (questionElements.length > 1) {
        const questionElement = document.querySelector(`[data-index="${index}"]`);
        if (questionElement) {
            questionElement.style.opacity = '0';
            questionElement.style.transform = 'translateX(-100%)';
            
            setTimeout(() => {
                questionElement.remove();
                reindexQuestions();
                updateQuestionCounter();
            }, 300);
        }
    } else {
        showToast('Un quiz doit avoir au moins une question', 'warning');
    }
}

function updateAnswerIndexes(questionIndex) {
    const answersList = document.getElementById(`answers-${questionIndex}`);
    const answerItems = answersList.querySelectorAll('.answer-item-expanded');
    
    answerItems.forEach((item, index) => {
        item.setAttribute('data-answer-index', index);
        const radio = item.querySelector('.answer-radio');
        radio.value = index;
        radio.name = `correct-${questionIndex}`;
    });
}

function reindexQuestions() {
    const questionsGrid = document.getElementById('questions-grid');
    const questionElements = questionsGrid.querySelectorAll('.question-item-expanded');
    
    questionElements.forEach((element, index) => {
        element.setAttribute('data-index', index);
        element.querySelector('.question-number-expanded').textContent = `Question ${index + 1}`;
        
        // Mettre à jour les événements et IDs des réponses
        const answersList = element.querySelector('.answers-grid-expanded');
        if (answersList) {
            answersList.id = `answers-${index}`;
            const radioInputs = answersList.querySelectorAll('.answer-radio');
            radioInputs.forEach(radio => {
                radio.name = `correct-${index}`;
            });
        }
    });
}

function updateQuestionCounter() {
    const questionsGrid = document.getElementById('questions-grid');
    const questionCount = questionsGrid.children.length;
    document.getElementById('questions-count').textContent = `${questionCount} question${questionCount > 1 ? 's' : ''}`;
}

// Soumission du quiz
async function submitQuizForm() {
    if (isSubmitting) return;
    
    const createBtn = document.getElementById('create-quiz-btn');
    createBtn.disabled = true;
    createBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Création...';
    isSubmitting = true;
    
    // Validation basique
    const title = document.getElementById('quiz-title').value.trim();
    const subject = document.getElementById('quiz-subject-select').value;
    
    if (!title || !subject) {
        showToast('Veuillez remplir le titre et la matière du quiz', 'warning');
        resetSubmitButton();
        return;
    }
    
    // Récupérer les questions
    const questions = [];
    const questionElements = document.querySelectorAll('.question-item-expanded');
    
    let isValid = true;
    
    for (const questionElement of questionElements) {
        const questionText = questionElement.querySelector('.question-input-expanded').value.trim();
        const answers = [];
        const answerInputs = questionElement.querySelectorAll('.answer-input-expanded');
        const correctRadio = questionElement.querySelector('.answer-radio:checked');
        
        if (!questionText) {
            isValid = false;
            showToast('Toutes les questions doivent avoir un texte', 'warning');
            break;
        }
        
        let hasEmptyAnswer = false;
        for (const input of answerInputs) {
            const answerText = input.value.trim();
            if (!answerText) {
                hasEmptyAnswer = true;
                break;
            }
            
            answers.push({
                answer_text: answerText,
                is_correct: correctRadio && parseInt(correctRadio.value) === Array.from(answerInputs).indexOf(input)
            });
        }
        
        if (hasEmptyAnswer) {
            isValid = false;
            showToast('Toutes les réponses doivent être remplies', 'warning');
            break;
        }
        
        if (answers.length < 2) {
            isValid = false;
            showToast('Chaque question doit avoir au moins 2 réponses', 'warning');
            break;
        }
        
        questions.push({
            question_text: questionText,
            question_type: 'multiple_choice',
            answers: answers
        });
    }
    
    if (!isValid || questions.length === 0) {
        resetSubmitButton();
        return;
    }
    
    // Soumettre les données
    const quizData = {
        title: title,
        subject: subject,
        description: document.getElementById('quiz-description').value.trim(),
        questions: questions
    };
    
    try {
        const response = await fetch('/api/quiz', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(quizData)
        });
        
        if (response.ok) {
            showToast('Quiz créé avec succès !', 'success');
            closeCreateQuizModal();
            loadQuizzes();
        } else {
            const error = await response.json();
            showToast('Erreur: ' + error.error, 'error');
        }
    } catch (error) {
        console.error('Erreur création quiz:', error);
        showToast('Erreur lors de la création du quiz', 'error');
    } finally {
        resetSubmitButton();
    }
}

function resetSubmitButton() {
    isSubmitting = false;
    const createBtn = document.getElementById('create-quiz-btn');
    createBtn.disabled = false;
    createBtn.innerHTML = '<i class="fas fa-rocket"></i> Créer le quiz';
}

// Passage du quiz
async function startQuiz(quizId) {
    try {
        const response = await fetch(`/api/quiz/${quizId}`);
        currentQuiz = await response.json();
        currentAttempt = [];
        currentQuestionIndex = 0;
        
        showQuizQuestion();
        document.getElementById('quiz-modal').style.display = 'flex';
    } catch (error) {
        console.error('Erreur chargement quiz:', error);
        showToast('Erreur lors du chargement du quiz', 'error');
    }
}

function showQuizQuestion() {
    if (!currentQuiz || !currentQuiz.questions.length) return;
    
    const question = currentQuiz.questions[currentQuestionIndex];
    const progress = `${currentQuestionIndex + 1}/${currentQuiz.questions.length}`;
    const progressPercent = ((currentQuestionIndex + 1) / currentQuiz.questions.length) * 100;
    
    document.getElementById('quiz-content').innerHTML = `
        <div class="quiz-progress-container">
            <div class="progress-bar">
                <div class="progress-fill" style="width: ${progressPercent}%"></div>
            </div>
            <div class="progress-text">
                <span>Question ${progress}</span>
                <span>${Math.round(progressPercent)}% terminé</span>
            </div>
        </div>
        
        <div class="question-card">
            <h3 class="question-text">${question.question_text}</h3>
            <div class="answers-grid">
                ${question.answers.map(answer => `
                    <div class="answer-option" onclick="selectAnswer(this, ${answer.id})">
                        ${answer.answer_text}
                    </div>
                `).join('')}
            </div>
        </div>
        
        <div class="quiz-navigation">
            ${currentQuestionIndex > 0 ? `
                <button class="btn-nav btn-prev" onclick="previousQuestion()">
                    <i class="fas fa-arrow-left"></i>
                    Précédent
                </button>
            ` : '<div></div>'}
            
            ${currentQuestionIndex < currentQuiz.questions.length - 1 ? `
                <button class="btn-nav btn-next" onclick="nextQuestion()">
                    Suivant
                    <i class="fas fa-arrow-right"></i>
                </button>
            ` : `
                <button class="btn-nav btn-submit" onclick="submitQuiz()">
                    Terminer le quiz
                    <i class="fas fa-check"></i>
                </button>
            `}
        </div>
    `;
    
    // Restaurer la sélection précédente si elle existe
    const previousAnswer = currentAttempt[currentQuestionIndex];
    if (previousAnswer) {
        const answerOptions = document.querySelectorAll('.answer-option');
        answerOptions.forEach(option => {
            if (parseInt(option.getAttribute('onclick').match(/\d+/)[0]) === previousAnswer.answer_id) {
                option.classList.add('selected');
            }
        });
    }
}

function selectAnswer(element, answerId) {
    // Désélectionner toutes les réponses
    document.querySelectorAll('.answer-option').forEach(opt => opt.classList.remove('selected'));
    // Sélectionner la réponse cliquée
    element.classList.add('selected');
    
    // Sauvegarder la réponse
    currentAttempt[currentQuestionIndex] = {
        question_id: currentQuiz.questions[currentQuestionIndex].id,
        answer_id: answerId
    };
}

function nextQuestion() {
    if (currentQuestionIndex < currentQuiz.questions.length - 1) {
        currentQuestionIndex++;
        showQuizQuestion();
    }
}

function previousQuestion() {
    if (currentQuestionIndex > 0) {
        currentQuestionIndex--;
        showQuizQuestion();
    }
}

async function submitQuiz() {
    try {
        const response = await fetch(`/api/quiz/${currentQuiz.id}/attempt`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ answers: currentAttempt.filter(a => a) })
        });
        
        const results = await response.json();
        showQuizResults(currentQuiz.id, results);
        
    } catch (error) {
        console.error('Erreur soumission quiz:', error);
        showToast('Erreur lors de la soumission du quiz', 'error');
    }
}

async function showQuizResults(quizId, recentResults = null) {
    try {
        const response = await fetch(`/api/quiz/${quizId}/attempts`);
        const attempts = await response.json();
        
        let content = `
            <div class="results-container">
                <h2>Résultats du Quiz</h2>
        `;
        
        if (recentResults) {
            const score = Math.round(recentResults.score);
            const scoreClass = score >= 80 ? 'score-excellent' : 
                              score >= 60 ? 'score-good' : 'score-poor';
            
            content += `
                <div class="score-circle" style="--score-percent: ${score}%">
                    <div class="score-text">${score}%</div>
                </div>
                <div class="score-message ${scoreClass}">${getScoreMessage(score)}</div>
                <div class="score-details">
                    ${recentResults.correct_answers}/${recentResults.total_questions} bonnes réponses
                </div>
            `;
        }
        
        if (attempts.length > 0) {
            content += `
                <div class="attempts-history">
                    <h3>Historique de vos tentatives</h3>
                    ${attempts.map(attempt => `
                        <div class="attempt-item">
                            <div class="attempt-score">Score: ${Math.round(attempt.score)}%</div>
                            <div class="attempt-details">
                                ${attempt.correct_answers}/${attempt.total_questions} bonnes réponses
                            </div>
                            <div class="attempt-date">
                                ${new Date(attempt.completed_at).toLocaleString('fr-FR')}
                            </div>
                        </div>
                    `).join('')}
                </div>
            `;
        }
        
        content += `
                <button class="btn-nav btn-primary" onclick="closeResultsModal(); closeQuizModal(); loadQuizzes();" style="margin-top: 20px;">
                    <i class="fas fa-home"></i>
                    Retour aux quiz
                </button>
            </div>
        `;
        
        document.getElementById('results-content').innerHTML = content;
        document.getElementById('results-modal').style.display = 'flex';
        document.getElementById('quiz-modal').style.display = 'none';
        
    } catch (error) {
        console.error('Erreur chargement résultats:', error);
        showToast('Erreur lors du chargement des résultats', 'error');
    }
}

function getScoreMessage(score) {
    if (score >= 90) return "🎉 Excellent ! Maîtrise parfaite !";
    if (score >= 75) return "👍 Très bien ! Bonne compréhension !";
    if (score >= 60) return "✅ Pas mal ! Continue comme ça !";
    if (score >= 50) return "💪 Encore un effort !";
    return "📚 Revoyons les bases ensemble !";
}

// Fonction pour afficher des notifications
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${type === 'warning' ? 'var(--warning)' : type === 'error' ? 'var(--error)' : 'var(--primary)'};
        color: white;
        padding: 12px 20px;
        border-radius: 8px;
        box-shadow: var(--shadow-lg);
        z-index: 10000;
        animation: slideInRight 0.3s ease;
        max-width: 400px;
        word-wrap: break-word;
    `;
    toast.textContent = message;
    
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'slideOutRight 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// Gestion de la fermeture des modaux
document.addEventListener('click', function(e) {
    if (e.target.classList.contains('modal-overlay')) {
        e.target.style.display = 'none';
    }
});

// Initialisation
document.addEventListener('DOMContentLoaded', function() {
    loadQuizzes();
    
    // Écouter les changements de filtres
    document.getElementById('quiz-subject')?.addEventListener('change', applyFilters);
    document.getElementById('quiz-sort')?.addEventListener('change', applyFilters);
    document.getElementById('quiz-search')?.addEventListener('input', applyFilters);
});

function applyFilters() {
    const subject = document.getElementById('quiz-subject')?.value || '';
    const sort = document.getElementById('quiz-sort')?.value || 'recent';
    const search = document.getElementById('quiz-search')?.value.toLowerCase() || '';
    
    let filtered = allQuizzes.filter(quiz => {
        const matchesSubject = !subject || quiz.subject === subject;
        const matchesSearch = !search || 
            quiz.title.toLowerCase().includes(search) ||
            quiz.description.toLowerCase().includes(search) ||
            quiz.subject.toLowerCase().includes(search);
        
        return matchesSubject && matchesSearch;
    });
    
    // Trier
    if (sort === 'recent') {
        filtered.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    } else if (sort === 'popular') {
        filtered.sort((a, b) => b.attempts_count - a.attempts_count);
    } else if (sort === 'questions') {
        filtered.sort((a, b) => b.questions_count - a.questions_count);
    } else if (sort === 'title') {
        filtered.sort((a, b) => a.title.localeCompare(b.title));
    }
    
    renderQuizzes(filtered);
}
// static/js/quiz-flashcard.js

let questionCount = 1;
let flashcardCount = 1;

function addQuestion() {
  const container = document.getElementById('questionsContainer');
  const group = document.createElement('div');
  group.className = 'question-group mb-3 p-3 border rounded';
  group.innerHTML = `
    <input type="text" class="form-control mb-2 question-text" placeholder="Question" required>
    <div class="options">
      <input type="text" class="form-control mb-1 option" placeholder="Option A" required>
      <input type="text" class="form-control mb-1 option" placeholder="Option B" required>
      <input type="text" class="form-control mb-1 option" placeholder="Option C">
      <input type="text" class="form-control mb-2 option" placeholder="Option D">
    </div>
    <div class="form-check">
      <input class="form-check-input correct-option" type="radio" name="correct${questionCount}" value="0" checked>
      <label class="form-check-label">A</label>
      <input class="form-check-input correct-option" type="radio" name="correct${questionCount}" value="1">
      <label class="form-check-label">B</label>
      <input class="form-check-input correct-option" type="radio" name="correct${questionCount}" value="2">
      <label class="form-check-label">C</label>
      <input class="form-check-input correct-option" type="radio" name="correct${questionCount}" value="3">
      <label class="form-check-label">D</label>
    </div>
  `;
  container.appendChild(group);
  questionCount++;
}

function addFlashcard() {
  const container = document.getElementById('cardsContainer');
  const group = document.createElement('div');
  group.className = 'card-group mb-3';
  group.innerHTML = `
    <div class="input-group mb-2">
      <span class="input-group-text">Avant</span>
      <input type="text" class="form-control front" placeholder="Terme..." required>
    </div>
    <div class="input-group mb-2">
      <span class="input-group-text">Arrière</span>
      <input type="text" class="form-control back" placeholder="Définition..." required>
    </div>
  `;
  container.appendChild(group);
  flashcardCount++;
}

// ================== QUIZ ==================
async function createQuiz(e) {
  e.preventDefault();
  const title = document.getElementById('quizTitle').value;
  const subject = document.getElementById('quizSubject').value;
  const questions = [];

  document.querySelectorAll('.question-group').forEach((group, idx) => {
    const qText = group.querySelector('.question-text').value;
    const options = Array.from(group.querySelectorAll('.option')).map(opt => opt.value).filter(v => v);
    const correctIndex = parseInt(group.querySelector(`input[name="correct${idx}"]:checked`).value);
    if (qText && options.length >= 2) {
      questions.push({ question: qText, options, correct_index: correctIndex });
    }
  });

  if (questions.length === 0) {
    alert("Ajoutez au moins une question valide.");
    return;
  }

  try {
    const res = await fetch('/api/quiz', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title, subject, questions })
    });
    if (res.ok) {
      alert("✅ Quiz publié !");
      document.getElementById('quizForm').reset();
      loadQuizzes();
    } else {
      const err = await res.json();
      alert("❌ " + (err.error || "Erreur"));
    }
  } catch (e) {
    alert("Erreur réseau");
  }
}

async function loadQuizzes() {
  try {
    const res = await fetch('/api/quizzes');
    const quizzes = await res.json();
    const container = document.getElementById('quizzesList');
    container.innerHTML = quizzes.length === 0 ? '<p class="text-muted">Aucun quiz pour le moment.</p>' :
      quizzes.map(q => `
        <div class="col-md-6 col-lg-4 mb-4">
          <div class="card h-100 shadow-sm">
            <div class="card-header">
              <strong>${q.title}</strong> <small class="text-muted">(${q.subject})</small>
            </div>
            <div class="card-body">
              <p class="mb-1"><small>Par ${q.username}</small></p>
              <p class="text-muted">${q.questions.length} questions</p>
            </div>
            <div class="card-footer text-end">
              <small class="text-muted">${new Date(q.created_at).toLocaleDateString()}</small>
            </div>
          </div>
        </div>
      `).join('');
  } catch (e) {
    console.error(e);
  }
}

// ================== FLASHCARDS ==================
async function createFlashcard(e) {
  e.preventDefault();
  const title = document.getElementById('fcTitle').value;
  const subject = document.getElementById('fcSubject').value;
  const cards = [];

  document.querySelectorAll('.card-group').forEach(group => {
    const front = group.querySelector('.front').value;
    const back = group.querySelector('.back').value;
    if (front && back) cards.push({ front, back });
  });

  if (cards.length === 0) {
    alert("Ajoutez au moins une carte valide.");
    return;
  }

  try {
    const res = await fetch('/api/flashcard', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title, subject, cards })
    });
    if (res.ok) {
      alert("✅ Flashcards publiées !");
      document.getElementById('flashcardForm').reset();
      loadFlashcards();
    } else {
      const err = await res.json();
      alert("❌ " + (err.error || "Erreur"));
    }
  } catch (e) {
    alert("Erreur réseau");
  }
}

async function loadFlashcards() {
  try {
    const res = await fetch('/api/flashcards');
    const flashcards = await res.json();
    const container = document.getElementById('flashcardsList');
    container.innerHTML = flashcards.length === 0 ? '<p class="text-muted">Aucun jeu de flashcards.</p>' :
      flashcards.map(f => `
        <div class="col-md-6 col-lg-4 mb-4">
          <div class="card h-100 shadow-sm">
            <div class="card-header">
              <strong>${f.title}</strong> <small>(${f.subject})</small>
            </div>
            <div class="card-body d-flex flex-column">
              <p class="mb-1"><small>Par ${f.username}</small></p>
              <p class="text-muted">${f.cards.length} cartes</p>
              <button class="btn btn-outline-primary btn-sm mt-auto" onclick="showFlashcards(${encodeURIComponent(JSON.stringify(f.cards))})">
                📖 Réviser
              </button>
            </div>
            <div class="card-footer text-end">
              <small class="text-muted">${new Date(f.created_at).toLocaleDateString()}</small>
            </div>
          </div>
        </div>
      `).join('');
  } catch (e) {
    console.error(e);
  }
}

// Afficher un jeu de flashcards en mode interactif
function showFlashcards(cardsStr) {
  const cards = JSON.parse(decodeURIComponent(cardsStr));
  let index = 0;

  const modal = document.createElement('div');
  modal.innerHTML = `
    <div class="modal fade show d-block" tabindex="-1">
      <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">Révision</h5>
            <button type="button" class="btn-close" onclick="closeModal()"></button>
          </div>
          <div class="modal-body text-center">
            <div class="flashcard-item" onclick="this.classList.toggle('flipped')">
              <div class="flashcard-inner">
                <div class="flashcard-front">${cards[0].front}</div>
                <div class="flashcard-back">${cards[0].back}</div>
              </div>
            </div>
            <p class="mt-3"><small>Carte 1 / ${cards.length}</small></p>
          </div>
          <div class="modal-footer">
            <button class="btn btn-secondary" onclick="prevCard(${encodeURIComponent(cardsStr)}, ${index})" ${index === 0 ? 'disabled' : ''}>⬅️</button>
            <button class="btn btn-primary" onclick="nextCard(${encodeURIComponent(cardsStr)}, ${index})" ${index === cards.length - 1 ? 'disabled' : ''}>➡️</button>
          </div>
        </div>
      </div>
    </div>
  `;
  document.body.appendChild(modal);
}

function closeModal() {
  document.querySelector('.modal').remove();
}

function nextCard(cardsStr, currentIndex) {
  const cards = JSON.parse(decodeURIComponent(cardsStr));
  const newIndex = currentIndex + 1;
  updateModal(cards, newIndex);
}

function prevCard(cardsStr, currentIndex) {
  const cards = JSON.parse(decodeURIComponent(cardsStr));
  const newIndex = currentIndex - 1;
  updateModal(cards, newIndex);
}

function updateModal(cards, index) {
  const modal = document.querySelector('.modal');
  modal.querySelector('.flashcard-front').textContent = cards[index].front;
  modal.querySelector('.flashcard-back').textContent = cards[index].back;
  modal.querySelector('.modal-body small').textContent = `Carte ${index + 1} / ${cards.length}`;
  modal.querySelector('.modal-footer button:first-child').disabled = index === 0;
  modal.querySelector('.modal-footer button:last-child').disabled = index === cards.length - 1;
  // Réinitialiser l'état retourné
  modal.querySelector('.flashcard-item').classList.remove('flipped');
}
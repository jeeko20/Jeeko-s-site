from notifications import notify_new_file, notify_new_quiz, notify_new_flashcard

if __name__ == '__main__':
    print('Test notification fichier...')
    ok = notify_new_file('exemple_test.pdf', 'DevLocal', 'pdf', link='https://example.com/exemple_test.pdf')
    print('Résultat notify_new_file:', ok)
    print('Test notification quiz...')
    ok2 = notify_new_quiz('Quiz de test', 'DevLocal', link='https://example.com/quiz#quiz-123')
    print('Résultat notify_new_quiz:', ok2)
    print('Test notification flashcard...')
    ok3 = notify_new_flashcard('Cartes de test', 'DevLocal', link='https://example.com/quiz#flashcard-321')
    print('Résultat notify_new_flashcard:', ok3)

from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
from datetime import datetime
import secrets
import json
import logging

# Initialize Flask app
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Generate a secure secret key
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database setup
def init_db():
    conn = sqlite3.connect('flashcard_app.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    # Flashcards table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS flashcards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            topic TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # MCQ Questions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS mcq_questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            question TEXT NOT NULL,
            option_a TEXT NOT NULL,
            option_b TEXT NOT NULL,
            option_c TEXT NOT NULL,
            option_d TEXT NOT NULL,
            correct_answer TEXT NOT NULL,
            topic TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # User Progress table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_progress (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            question_id INTEGER NOT NULL,
            user_answer TEXT,
            is_correct BOOLEAN,
            attempt_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (question_id) REFERENCES mcq_questions (id)
        )
    ''')
    
    conn.commit()
    conn.close()

# Initialize database
init_db()

# Helper functions
def get_db_connection():
    conn = sqlite3.connect('flashcard_app.db')
    conn.row_factory = sqlite3.Row
    return conn

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('auth'))

@app.route('/auth')
def auth():
    return render_template('auth.html')

@app.route('/api/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        # Validation
        if not name or not email or not password:
            return jsonify({'error': 'All fields are required'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters long'}), 400
        
        if '@' not in email:
            return jsonify({'error': 'Please enter a valid email address'}), 400
        
        # Check if user already exists
        conn = get_db_connection()
        existing_user = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
        
        if existing_user:
            conn.close()
            return jsonify({'error': 'Email already registered'}), 400
        
        # Create new user
        password_hash = generate_password_hash(password)
        cursor = conn.execute(
            'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
            (name, email, password_hash)
        )
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        # Create session
        session['user_id'] = user_id
        session['user_name'] = name
        session['user_email'] = email
        
        logger.info(f"New user registered: {email}")
        return jsonify({'success': True, 'message': 'Account created successfully!'}), 201
        
    except Exception as e:
        logger.error(f"Signup error: {str(e)}")
        return jsonify({'error': 'Registration failed. Please try again.'}), 500

@app.route('/api/signin', methods=['POST'])
def signin():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        # Check user credentials
        conn = get_db_connection()
        user = conn.execute(
            'SELECT id, name, email, password_hash FROM users WHERE email = ?',
            (email,)
        ).fetchone()
        
        if not user or not check_password_hash(user['password_hash'], password):
            conn.close()
            return jsonify({'error': 'Invalid email or password'}), 401
        
        # Update last login
        conn.execute(
            'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
            (user['id'],)
        )
        conn.commit()
        conn.close()
        
        # Create session
        session['user_id'] = user['id']
        session['user_name'] = user['name']
        session['user_email'] = user['email']
        
        logger.info(f"User logged in: {email}")
        return jsonify({'success': True, 'message': 'Welcome back!'}), 200
        
    except Exception as e:
        logger.error(f"Signin error: {str(e)}")
        return jsonify({'error': 'Login failed. Please try again.'}), 500

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('auth'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', 
                         user_name=session.get('user_name', 'Student'),
                         user_email=session.get('user_email', ''))

@app.route('/api/generate-flashcards', methods=['POST'])
@login_required
def generate_flashcards():
    try:
        data = request.get_json()
        prompt = data.get('prompt', '').strip()
        topic = data.get('topic', 'General').strip()
        
        if not prompt:
            return jsonify({'error': 'Please provide a prompt or topic'}), 400
        
        # Simulate AI-generated flashcards (replace with actual AI integration)
        flashcards = generate_mock_flashcards(prompt, topic)
        
        # Save flashcards to database
        conn = get_db_connection()
        for card in flashcards:
            conn.execute(
                'INSERT INTO flashcards (user_id, title, content, topic) VALUES (?, ?, ?, ?)',
                (session['user_id'], card['title'], card['content'], topic)
            )
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'flashcards': flashcards}), 200
        
    except Exception as e:
        logger.error(f"Generate flashcards error: {str(e)}")
        return jsonify({'error': 'Failed to generate flashcards'}), 500

@app.route('/api/generate-mcq', methods=['POST'])
@login_required
def generate_mcq():
    try:
        data = request.get_json()
        prompt = data.get('prompt', '').strip()
        topic = data.get('topic', 'General').strip()
        num_questions = min(int(data.get('num_questions', 5)), 10)  # Max 10 questions
        
        if not prompt:
            return jsonify({'error': 'Please provide a prompt or topic'}), 400
        
        # Simulate AI-generated MCQ questions (replace with actual AI integration)
        questions = generate_mock_mcq(prompt, topic, num_questions)
        
        # Save questions to database
        conn = get_db_connection()
        question_ids = []
        for q in questions:
            cursor = conn.execute(
                '''INSERT INTO mcq_questions 
                   (user_id, question, option_a, option_b, option_c, option_d, correct_answer, topic) 
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                (session['user_id'], q['question'], q['options']['A'], q['options']['B'], 
                 q['options']['C'], q['options']['D'], q['correct_answer'], topic)
            )
            question_ids.append(cursor.lastrowid)
        conn.commit()
        conn.close()
        
        # Add IDs to questions
        for i, q in enumerate(questions):
            q['id'] = question_ids[i]
        
        return jsonify({'success': True, 'questions': questions}), 200
        
    except Exception as e:
        logger.error(f"Generate MCQ error: {str(e)}")
        return jsonify({'error': 'Failed to generate MCQ questions'}), 500

@app.route('/api/submit-answer', methods=['POST'])
@login_required
def submit_answer():
    try:
        data = request.get_json()
        question_id = data.get('question_id')
        user_answer = data.get('user_answer', '').strip().upper()
        
        if not question_id or not user_answer:
            return jsonify({'error': 'Question ID and answer are required'}), 400
        
        # Get the correct answer
        conn = get_db_connection()
        question = conn.execute(
            'SELECT correct_answer FROM mcq_questions WHERE id = ?',
            (question_id,)
        ).fetchone()
        
        if not question:
            conn.close()
            return jsonify({'error': 'Question not found'}), 404
        
        correct_answer = question['correct_answer']
        is_correct = user_answer == correct_answer
        
        # Save user's attempt
        conn.execute(
            'INSERT INTO user_progress (user_id, question_id, user_answer, is_correct) VALUES (?, ?, ?, ?)',
            (session['user_id'], question_id, user_answer, is_correct)
        )
        conn.commit()
        conn.close()
        
        # Generate response message
        if is_correct:
            messages = [
                "🎉 Brilliant! You got it right!",
                "⭐ Excellent work! Keep it up!",
                "🚀 Amazing! You're on fire!",
                "💯 Perfect! You're a learning superstar!",
                "🌟 Outstanding! Your hard work is paying off!"
            ]
            message = secrets.choice(messages)
        else:
            messages = [
                "💪 Don't worry! Mistakes make people gain more knowledge. Review the flashcard and try again!",
                "🌱 Every mistake is a learning opportunity! Check the concept and come back stronger!",
                "📚 No problem! Learning is a journey. Review the material and you'll nail it next time!",
                "🎯 Close one! Remember, mistakes help us grow. Study the flashcard and try again!",
                "🧠 That's how we learn! Check the correct answer, review the concept

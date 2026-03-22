# Automated Interview Evaluation & Malpractice Detection System

## Setup Instructions
1. Clone the repository
2. Create virtual environment: `python -m venv venv`
3. Activate: `venv\Scripts\activate` (Windows) or `source venv/bin/activate` (Mac/Linux)
4. Install dependencies: `pip install -r requirements.txt`
5. Copy `.env.example` to `.env` and fill in your values
6. Run: `python app.py`

## Environment Variables
See `.env.example` for all required variables.
Never commit your `.env` file.

## Seeding Sample Data (For Demo)
Run `python seed_data.py` to load sample candidates and questions.

## Tech Stack
Flask, MongoDB, Python, HTML/CSS

## Security Features
- CSRF protection on all forms
- Input sanitization with bleach
- Password hashing with werkzeug
- Rate limiting on login and submit routes
- Session timeout after 2 hours
- NoSQL injection prevention
- Security headers via flask-talisman

## Malpractice Detection Signals
1. Text similarity (TF-IDF + difflib)
2. Submission time pattern analysis
3. Answer sequence fingerprinting
4. Writing style fingerprinting
5. Score anomaly detection
6. Edit distance / paraphrase check

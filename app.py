import os
import uuid
from datetime import datetime
from functools import wraps
from io import BytesIO
from difflib import SequenceMatcher

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_file, jsonify, abort
)
from pymongo import MongoClient
from bson.objectid import ObjectId
from bson.errors import InvalidId
from dotenv import load_dotenv
from fpdf import FPDF
import re
import bleach
import validators
from datetime import timedelta
from werkzeug.security import check_password_hash
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.errors import RateLimitExceeded

from malpractice_engine import run_full_detection

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "fallback-secret-key")

# Session Security
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    SESSION_COOKIE_SECURE=os.getenv("FLASK_ENV") == "production",
    WTF_CSRF_TIME_LIMIT=3600
)

# CSRF Setup
csrf = CSRFProtect(app)

# Security Headers setup via Talisman
csp = {
    'default-src': '\'self\'',
    'script-src': '\'self\'',
    'style-src': ['\'self\'', '\'unsafe-inline\''],
    'img-src': '\'self\'',
    'font-src': '\'self\''
}
Talisman(app,
    content_security_policy=csp,
    force_https=os.getenv("FLASK_ENV") == "production",
    strict_transport_security=False,
    session_cookie_secure=os.getenv("FLASK_ENV") == "production",
    session_cookie_http_only=True,
    referrer_policy='strict-origin-when-cross-origin'
)

# Rate Limiter setup
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

MONGO_URI = os.getenv("MONGO_URI")

if not MONGO_URI:
    raise RuntimeError("MONGO_URI environment variable is not set.")

if not MONGO_URI.startswith("mongodb"):
    raise RuntimeError(f"MONGO_URI invalid. Value starts with: '{MONGO_URI[:20]}'")

client = MongoClient(MONGO_URI)
db = client[os.getenv('DB_NAME', 'interview_eval')]

# Collections
questions_col = db["questions"]
allowed_candidates_col = db["allowed_candidates"]
submissions_col = db["submissions"]
risk_results_col = db["risk_results"]

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH", "")

failed_attempts = {}

# ---------------------------------------------------------------------------
# Validation & Error Handlers
# ---------------------------------------------------------------------------

def safe_object_id(id_str):
    try:
        return ObjectId(id_str)
    except (InvalidId, TypeError, ValueError):
        abort(400)

def contains_mongo_operators(value):
    return isinstance(value, str) and '$' in value

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash('Session expired or invalid request. Please try again.', 'danger')
    return redirect(url_for('login'))

@app.errorhandler(RateLimitExceeded)
def handle_rate_limit(e):
    flash('Too many requests. Please slow down.', 'danger')
    return redirect(url_for('login'))

@app.before_request
def check_session_timeout():
    if 'logged_in' in session:
        last_active = session.get('last_active')
        if last_active:
            elapsed = (datetime.now() - datetime.fromisoformat(last_active)).seconds
            if elapsed > 7200:
                session.clear()
                flash('Session expired. Please login again.', 'warning')
                return redirect(url_for('login'))
        session['last_active'] = datetime.now().isoformat()

# ---------------------------------------------------------------------------
# Auth helper
# ---------------------------------------------------------------------------
def login_required(f):
    """Decorator that protects routes behind recruiter login."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            flash("Please log in to access the dashboard.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Malpractice detection  (updated for new submissions schema)
# ---------------------------------------------------------------------------
def detect_malpractice(submissions_list):
    """Compare every pair of submissions on text-answer similarity and
    submission-time proximity.

    Returns dict keyed by candidate email:
        { email: { "similarity_score": float, "time_flag": bool,
                    "similar_to": str | None } }
    """
    results = {}

    # Collect all text answers per submission
    for s in submissions_list:
        text_answers = []
        answers = s.get("answers", {})
        # Gather all text-type answers
        for qid, ans in answers.items():
            if isinstance(ans, str) and len(ans) > 30:
                text_answers.append(ans)
        s["_text_answers"] = text_answers

        results[s["email"]] = {
            "similarity_score": 0.0,
            "time_flag": False,
            "similar_to": None,
        }

    n = len(submissions_list)
    for i in range(n):
        for j in range(i + 1, n):
            s1 = submissions_list[i]
            s2 = submissions_list[j]

            # --- Text similarity ---
            sims = []
            pairs = min(len(s1["_text_answers"]), len(s2["_text_answers"]))
            for k in range(pairs):
                ratio = SequenceMatcher(
                    None, s1["_text_answers"][k], s2["_text_answers"][k]
                ).ratio()
                sims.append(ratio)

            avg_sim = (sum(sims) / len(sims) * 100) if sims else 0.0

            # --- Time proximity ---
            t1 = s1.get("submit_time")
            t2 = s2.get("submit_time")
            time_flag = False
            if t1 and t2:
                diff = abs((t1 - t2).total_seconds())
                if diff <= 120:
                    time_flag = True

            # Keep worst similarity for each
            if avg_sim > results[s1["email"]]["similarity_score"]:
                results[s1["email"]]["similarity_score"] = round(avg_sim, 2)
                results[s1["email"]]["similar_to"] = s2["email"]
            if avg_sim > results[s2["email"]]["similarity_score"]:
                results[s2["email"]]["similarity_score"] = round(avg_sim, 2)
                results[s2["email"]]["similar_to"] = s1["email"]

            if time_flag:
                results[s1["email"]]["time_flag"] = True
                results[s2["email"]]["time_flag"] = True

    return results


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------
def calculate_risk(similarity_score, time_flag):
    """Return 'Low', 'Medium', or 'High' risk label."""
    if similarity_score > 70:
        return "High"
    if similarity_score >= 40 or time_flag:
        return "Medium"
    return "Low"


def _build_reason(similarity_score, time_flag, similar_to):
    """Human-readable reason string."""
    parts = []
    if similarity_score > 70:
        parts.append(f"High answer similarity ({similarity_score:.1f}%) with {similar_to}")
    elif similarity_score >= 40:
        parts.append(f"Moderate answer similarity ({similarity_score:.1f}%) with {similar_to}")
    if time_flag:
        parts.append("Submitted within 2 min of another candidate")
    return "; ".join(parts) if parts else "No issues detected"


# ===================================================================
# ROUTES — Auth
# ===================================================================
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        ip = get_remote_address()
        now = datetime.now()
        
        # Brute force check
        attempt_info = failed_attempts.get(ip, {'count': 0, 'last_attempt': now})
        if attempt_info['count'] >= 5:
            elapsed = (now - attempt_info['last_attempt']).seconds
            if elapsed < 900: # 15 minutes
                flash("Too many failed attempts. Try again in 15 minutes.", "danger")
                return render_template("login.html")
            else:
                # Reset after 15 mins
                attempt_info['count'] = 0

        username = request.form.get("username", "")
        password = request.form.get("password", "")
        
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session.clear() # clear existing to prevent session fixation
            session["logged_in"] = True
            session['last_active'] = now.isoformat()
            if ip in failed_attempts:
                del failed_attempts[ip]
            flash("Logged in successfully!", "success")
            return redirect(url_for("dashboard"))
        
        # Log failed attempt
        attempt_info['count'] += 1
        attempt_info['last_attempt'] = now
        failed_attempts[ip] = attempt_info
        
        flash("Invalid credentials. Please try again.", "danger")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))


# ===================================================================
# ROUTES — Home (redirects to login or dashboard)
# ===================================================================
@app.route("/")
def index():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


# ===================================================================
# ROUTES — Question Builder  (PROMPT 9)
# ===================================================================
@app.route("/questions")
@login_required
def questions():
    all_questions = list(questions_col.find().sort("created_at", -1))
    return render_template("questions.html", questions=all_questions)


@app.route("/questions/add", methods=["POST"])
@login_required
def add_question():
    q_type = request.form.get("type", "mcq")
    q_text = request.form.get("question_text", "")

    if not q_text or len(q_text.strip()) == 0:
        flash("Question text cannot be empty.", "danger")
        return redirect(url_for("questions"))
        
    if len(q_text) > 1000:
        flash("Question text is too long (limit: 1000 characters).", "danger")
        return redirect(url_for("questions"))

    doc = {
        "question_text": bleach.clean(q_text.strip(), tags=[], strip=True),
        "type": q_type,
        "options": [],
        "correct_answer": "",
        "created_at": datetime.utcnow(),
    }

    if q_type == "mcq":
        opt_a = request.form.get("option_a", "").strip()
        opt_b = request.form.get("option_b", "").strip()
        opt_c = request.form.get("option_c", "").strip()
        opt_d = request.form.get("option_d", "").strip()
        correct = request.form.get("correct_answer", "").strip()
        
        if not all([opt_a, opt_b, opt_c, opt_d]):
            flash("MCQ must have exactly 4 non-empty options.", "danger")
            return redirect(url_for("questions"))
        if not correct:
            flash("MCQ correct answer must be selected.", "danger")
            return redirect(url_for("questions"))
            
        doc["options"] = [
            bleach.clean(o, tags=[], strip=True) for o in [opt_a, opt_b, opt_c, opt_d]
        ]
        doc["correct_answer"] = bleach.clean(correct, tags=[], strip=True)
        
    elif q_type == "truefalse":
        correct = request.form.get("correct_answer", "").strip()
        if not correct:
            flash("True/False correct answer must be selected.", "danger")
            return redirect(url_for("questions"))
        doc["options"] = ["True", "False"]
        doc["correct_answer"] = bleach.clean(correct, tags=[], strip=True)
        
    elif q_type == "fillintheblank":
        correct = request.form.get("correct_answer", "").strip()
        if not correct:
            flash("Fill-in-the-blank correct answer must not be empty.", "danger")
            return redirect(url_for("questions"))
        doc["correct_answer"] = bleach.clean(correct, tags=[], strip=True)

    questions_col.insert_one(doc)
    flash("Question added successfully!", "success")
    return redirect(url_for("questions"))


@app.route("/questions/delete/<qid>", methods=["POST"])
@login_required
def delete_question(qid):
    safe_id = safe_object_id(qid)
    questions_col.delete_one({"_id": safe_id})
    flash("Question deleted.", "info")
    return redirect(url_for("questions"))


# ===================================================================
# ROUTES — Candidate Management & Unique Links  (PROMPT 10)
# ===================================================================
@app.route("/candidates")
@login_required
def candidates():
    all_candidates = list(allowed_candidates_col.find().sort("created_at", -1))
    base_url = request.host_url.rstrip("/")
    return render_template("candidates.html", candidates=all_candidates, base_url=base_url)


@app.route("/candidates/add", methods=["POST"])
@login_required
def add_candidate():
    name = request.form.get("name", "").strip()
    raw_email = request.form.get("email", "").strip().lower()

    if not name or not raw_email:
        flash("Name and email are required.", "danger")
        return redirect(url_for("candidates"))
        
    if len(name) > 100 or len(raw_email) > 200:
        flash('Input too long', 'danger')
        return redirect(url_for("candidates"))

    email = bleach.clean(raw_email, tags=[], strip=True)
    if not validators.email(email):
        flash('Invalid email address', 'danger')
        return redirect(url_for("candidates"))
        
    if contains_mongo_operators(email):
        abort(400)

    # Check for duplicate email
    if allowed_candidates_col.find_one({"email": email}):
        flash("A candidate with this email already exists.", "warning")
        return redirect(url_for("candidates"))

    token = str(uuid.uuid4())
    allowed_candidates_col.insert_one({
        "name": bleach.clean(name, tags=[], strip=True),
        "email": email,
        "token": token,
        "status": "pending",
        "created_at": datetime.utcnow(),
    })
    flash(f"Candidate added! Test link generated.", "success")
    return redirect(url_for("candidates"))


@app.route("/candidates/delete/<cid>", methods=["POST"])
@login_required
def delete_candidate(cid):
    safe_id = safe_object_id(cid)
    allowed_candidates_col.delete_one({"_id": safe_id})
    flash("Candidate removed.", "info")
    return redirect(url_for("candidates"))


# ===================================================================
# ROUTES — Dynamic Test Page  (PROMPT 11)
# ===================================================================
@app.route("/test/<token>")
def take_test(token):
    if not re.match(r'^[a-zA-Z0-9\-]+$', token):
        abort(400)
    candidate = allowed_candidates_col.find_one({"token": token})
    if not candidate:
        return render_template("test_error.html",
                               title="Invalid Link",
                               message="This test link is invalid or does not exist.")
    if candidate["status"] == "completed":
        return render_template("test_error.html",
                               title="Already Completed",
                               message="You have already taken this test. Thank you!")

    all_questions = list(questions_col.find().sort("created_at", 1))

    if not all_questions:
        return render_template("test_error.html",
                               title="No Questions Available",
                               message="The recruiter has not added any questions yet. Please try again later.")

    return render_template("test_dynamic.html",
                           candidate=candidate,
                           questions=all_questions,
                           token=token)


# ===================================================================
# ROUTES — Answer Submission & Evaluation  (PROMPT 12)
# ===================================================================
@app.route("/submit/<token>", methods=["POST"])
@limiter.limit("3 per hour")
def submit_test(token):
    if not re.match(r'^[a-zA-Z0-9\-]+$', token):
        abort(400)
    candidate = allowed_candidates_col.find_one({"token": token})
    if not candidate:
        flash("Invalid test link.", "danger")
        return redirect(url_for("index"))
    if candidate["status"] == "completed":
        return render_template("test_error.html",
                               title="Already Completed",
                               message="You have already submitted this test.")

    all_questions = list(questions_col.find())
    answers = {}
    correct_count = 0
    auto_gradable = 0
    text_pending = False

    for q in all_questions:
        qid = str(q["_id"])
        submitted = request.form.get(f"answer_{qid}", "")
        
        if len(submitted) > 5000:
            flash("Answer too long", "danger")
            return redirect(url_for("take_test", token=token))
            
        clean_answer = bleach.clean(submitted, tags=[], strip=True)
        answers[qid] = clean_answer

        if q["type"] in ("mcq", "truefalse"):
            auto_gradable += 1
            if clean_answer.lower() == q.get("correct_answer", "").lower():
                correct_count += 1
        elif q["type"] == "fillintheblank":
            auto_gradable += 1
            if clean_answer.lower() == q.get("correct_answer", "").lower():
                correct_count += 1
        elif q["type"] == "text":
            text_pending = True

    auto_score = round((correct_count / auto_gradable * 100), 2) if auto_gradable > 0 else 0.0

    submissions_col.insert_one({
        "token": token,
        "name": candidate["name"],
        "email": candidate["email"],
        "answers": answers,
        "auto_score": auto_score,
        "manual_score": None,
        "final_score": None,
        "text_answers_pending": text_pending,
        "submit_time": datetime.utcnow(),
    })

    # Mark candidate as completed
    allowed_candidates_col.update_one(
        {"_id": candidate["_id"]},
        {"$set": {"status": "completed"}}
    )

    return render_template("thankyou.html")


# ===================================================================
# ROUTES — Recruiter Dashboard  (PROMPT 13 + 22)
# ===================================================================
@app.route("/dashboard")
@login_required
def dashboard():
    total_questions = questions_col.count_documents({})
    total_candidates = allowed_candidates_col.count_documents({})
    pending_count = allowed_candidates_col.count_documents({"status": "pending"})
    completed_count = allowed_candidates_col.count_documents({"status": "completed"})

    submissions = list(submissions_col.find())

    # Try to use advanced risk_results first; fall back to basic detection
    risk_results = {r["email"]: r for r in risk_results_col.find()}
    use_advanced = len(risk_results) > 0

    if not use_advanced:
        malpractice = detect_malpractice(submissions)

    risk_filter = request.args.get("risk", "all").lower()

    rows = []
    high_risk_count = 0
    for s in submissions:
        email = s["email"]

        if use_advanced and email in risk_results:
            rr = risk_results[email]
            risk = rr.get("risk_level", "Low")
            reason = "; ".join(rr.get("reasons", ["No issues detected"]))
            sim = round(rr.get("final_score", 0) * 100, 1)
            confidence = rr.get("confidence", "0%")
        else:
            info = malpractice.get(email, {}) if not use_advanced else {}
            sim_raw = info.get("similarity_score", 0)
            tf = info.get("time_flag", False)
            risk = calculate_risk(sim_raw, tf)
            reason = _build_reason(sim_raw, tf, info.get("similar_to"))
            sim = sim_raw
            confidence = None

        if risk == "High":
            high_risk_count += 1

        if risk_filter != "all" and risk.lower() != risk_filter:
            continue

        review_status = "Reviewed" if not s.get("text_answers_pending", True) else "Pending Review"
        if s.get("manual_score") is not None:
            review_status = "Reviewed"

        final_score = s.get("final_score")
        if final_score is None:
            final_score = s.get("auto_score", 0)

        # Find the most-similar candidate for compare link
        compare_with = None
        if use_advanced and email in risk_results:
            rr = risk_results[email]
            for r_reason in rr.get("reasons", []):
                if "with " in r_reason:
                    compare_with = r_reason.split("with ")[-1].split(" ")[0].strip()
                    break

        rows.append({
            "id": str(s["_id"]),
            "name": s["name"],
            "email": s["email"],
            "auto_score": s.get("auto_score", 0),
            "final_score": round(final_score, 1),
            "review_status": review_status,
            "risk": risk,
            "reason": reason,
            "similarity": sim,
            "confidence": confidence,
            "compare_with": compare_with,
        })

    detection_ran = use_advanced
    return render_template("dashboard.html",
                           rows=rows,
                           total_questions=total_questions,
                           total_candidates=total_candidates,
                           pending_count=pending_count,
                           completed_count=completed_count,
                           high_risk_count=high_risk_count,
                           risk_filter=risk_filter,
                           detection_ran=detection_ran)


# ===================================================================
# ROUTES — Review Answers  (PROMPT 13)
# ===================================================================
@app.route("/review/<submission_id>")
@login_required
def review(submission_id):
    safe_id = safe_object_id(submission_id)
    submission = submissions_col.find_one({"_id": safe_id})
    if not submission:
        flash("Submission not found.", "danger")
        return redirect(url_for("dashboard"))

    all_questions = list(questions_col.find())
    q_map = {str(q["_id"]): q for q in all_questions}

    # Build review data
    review_items = []
    for qid, answer in submission.get("answers", {}).items():
        q = q_map.get(qid)
        if not q:
            continue
        is_correct = None
        if q["type"] in ("mcq", "truefalse"):
            is_correct = answer.lower() == q.get("correct_answer", "").lower()
        elif q["type"] == "fillintheblank":
            is_correct = answer.strip().lower() == q.get("correct_answer", "").strip().lower()

        review_items.append({
            "question_text": q["question_text"],
            "type": q["type"],
            "correct_answer": q.get("correct_answer", ""),
            "submitted_answer": answer,
            "is_correct": is_correct,
            "options": q.get("options", []),
        })

    # Run malpractice for this candidate
    all_subs = list(submissions_col.find())
    malpractice = detect_malpractice(all_subs)
    info = malpractice.get(submission["email"], {})
    sim = info.get("similarity_score", 0)
    tf = info.get("time_flag", False)
    risk = calculate_risk(sim, tf)
    reason = _build_reason(sim, tf, info.get("similar_to"))

    return render_template("review.html",
                           submission=submission,
                           review_items=review_items,
                           risk=risk,
                           reason=reason,
                           similarity=sim)


@app.route("/review/<submission_id>/score", methods=["POST"])
@login_required
def score_submission(submission_id):
    safe_id = safe_object_id(submission_id)
    submission = submissions_col.find_one({"_id": safe_id})
    if not submission:
        flash("Submission not found.", "danger")
        return redirect(url_for("dashboard"))

    try:
        manual_score = float(request.form.get("manual_score", 0))
    except ValueError:
        manual_score = 0.0

    # Combine: auto_score weighted + manual_score weighted
    auto_score = submission.get("auto_score", 0)

    # Count auto-gradable vs text questions to weight properly
    all_questions = list(questions_col.find())
    auto_count = sum(1 for q in all_questions if q["type"] in ("mcq", "truefalse", "fillintheblank"))
    text_count = sum(1 for q in all_questions if q["type"] == "text")
    total = auto_count + text_count

    if total > 0:
        auto_weight = auto_count / total
        text_weight = text_count / total
        final_score = round((auto_score * auto_weight) + (manual_score * text_weight), 2)
    else:
        final_score = auto_score

    submissions_col.update_one(
        {"_id": ObjectId(submission_id)},
        {"$set": {
            "manual_score": manual_score,
            "final_score": final_score,
            "text_answers_pending": False,
        }}
    )
    flash(f"Manual score saved. Final score: {final_score}%", "success")
    return redirect(url_for("dashboard"))


# ===================================================================
# ROUTES — PDF Report  (uses risk_results from 6-signal engine)
# ===================================================================
@app.route("/report/<submission_id>")
@login_required
def report(submission_id):
    safe_id = safe_object_id(submission_id)
    submission = submissions_col.find_one({"_id": safe_id})
    if not submission:
        flash("Submission not found.", "danger")
        return redirect(url_for("dashboard"))

    # Pull risk data from the 6-signal engine results
    risk_info = risk_results_col.find_one({"email": submission["email"]}) or {}

    risk_level = risk_info.get("risk_level", "Not analysed")
    confidence = risk_info.get("confidence", "N/A")
    reasons = risk_info.get("reasons", ["Detection not yet run"])
    breakdown = risk_info.get("signal_breakdown", {})

    final_score = submission.get("final_score") or submission.get("auto_score", 0)

    # Fetch questions for the answer listing
    all_questions = list(questions_col.find().sort("created_at", 1))
    q_map = {str(q["_id"]): q for q in all_questions}

    # --- Build PDF ---
    pdf = FPDF()
    pdf.add_page()

    # Title
    pdf.set_font("Helvetica", "B", 22)
    pdf.cell(0, 14, "Interview Evaluation Report", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(4)

    # Divider
    pdf.set_draw_color(52, 73, 94)
    pdf.set_line_width(0.8)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(6)

    # ----- Section 1: Candidate Details -----
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "1. Candidate Details", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 8, f"Name:       {submission['name']}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Email:      {submission['email']}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Auto Score: {submission.get('auto_score', 0):.1f}%", new_x="LMARGIN", new_y="NEXT")
    if submission.get("manual_score") is not None:
        pdf.cell(0, 8, f"Manual Score: {submission['manual_score']:.1f}%", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Final Score: {final_score:.1f}%", new_x="LMARGIN", new_y="NEXT")
    submit_time = submission.get("submit_time")
    if submit_time:
        pdf.cell(0, 8, f"Submitted:  {submit_time.strftime('%Y-%m-%d %H:%M:%S')}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # ----- Section 2: Risk Assessment -----
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "2. Malpractice Risk Assessment", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 8, f"Risk Level:  {risk_level}  ({confidence})", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    # Signal breakdown table
    if breakdown:
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, "6-Signal Breakdown:", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)

        signal_labels = [
            ("Text Similarity", "text_similarity", "35%"),
            ("Time Pattern", "time_pattern", "20%"),
            ("Sequence Match", "sequence_match", "15%"),
            ("Style Match", "style_match", "15%"),
            ("Score Anomaly", "score_anomaly", "10%"),
            ("Edit Distance", "edit_distance", "5%"),
        ]
        for label, key, weight in signal_labels:
            val = breakdown.get(key, 0)
            line = f"  {label} (weight {weight}): {val * 100:.1f}%"
            pdf.cell(0, 7, line, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    # Reasons
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 8, "Reasons:", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    for reason in reasons:
        safe_reason = reason.encode("latin-1", "replace").decode("latin-1")
        pdf.cell(0, 6, f"  - {safe_reason}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # ----- Section 3: Answers -----
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "3. Candidate Answers", new_x="LMARGIN", new_y="NEXT")

    answers = submission.get("answers", {})
    q_num = 0
    for q in all_questions:
        qid = str(q["_id"])
        ans = answers.get(qid, "(No answer)")
        q_num += 1

        # Check page space — add new page if running low
        if pdf.get_y() > 250:
            pdf.add_page()

        q_type = q.get("type", "text").upper()
        correct = q.get("correct_answer", "")

        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 7, f"Q{q_num} [{q_type}]: {q['question_text'][:90]}", new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", "", 10)
        if q.get("type") in ("mcq", "truefalse", "fillintheblank") and correct:
            is_correct = str(ans).strip().lower() == str(correct).strip().lower()
            status = "CORRECT" if is_correct else "WRONG"
            pdf.cell(0, 6, f"  Answer: {ans}  [{status}]  (Correct: {correct})", new_x="LMARGIN", new_y="NEXT")
        else:
            # Text / coding answer — may be multi-line
            safe_ans = str(ans).encode("latin-1", "replace").decode("latin-1")
            pdf.cell(0, 6, "  Answer:", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Courier", "", 9)
            for line in safe_ans.split("\n"):
                if pdf.get_y() > 270:
                    pdf.add_page()
                pdf.cell(0, 5, f"    {line[:100]}", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 10)
        pdf.ln(2)

    # Footer
    pdf.ln(6)
    pdf.set_draw_color(52, 73, 94)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)
    pdf.set_font("Helvetica", "I", 9)
    pdf.cell(0, 8, f"Report generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}  |  Interview Evaluation System", align="C")

    buf = BytesIO()
    pdf.output(buf)
    buf.seek(0)

    safe_email = submission['email'].replace('@', '_at_').replace('.', '_')
    return send_file(
        buf,
        as_attachment=True,
        download_name=f"report_{safe_email}.pdf",
        mimetype="application/pdf",
    )


# ===================================================================
# ROUTES — Thank You
# ===================================================================
@app.route("/thankyou")
def thankyou():
    return render_template("thankyou.html")


# ===================================================================
# ROUTES — Run Malpractice Detection Engine  (PROMPT 22)
# ===================================================================
@app.route("/run-detection")
@login_required
@limiter.limit("10 per hour")
def run_detection():
    submissions = list(submissions_col.find())
    if not submissions:
        flash("No submissions to analyse.", "warning")
        return redirect(url_for("dashboard"))

    all_questions = list(questions_col.find())
    questions_map = {str(q["_id"]): q for q in all_questions}

    # Run all 6 signals
    results = run_full_detection(submissions, questions_map)

    # Save to MongoDB (upsert per email)
    high_count = 0
    for r in results:
        r["analysed_at"] = datetime.utcnow()
        risk_results_col.update_one(
            {"email": r["email"]},
            {"$set": r},
            upsert=True,
        )
        if r["risk_level"] == "High":
            high_count += 1

    flash(
        f"Detection complete. {len(results)} candidates analysed. "
        f"{high_count} flagged as High risk.",
        "success",
    )
    return redirect(url_for("dashboard"))


# ===================================================================
# ROUTES — Pair Comparison View  (PROMPT 23)
# ===================================================================
@app.route("/compare/<path:email_a>/<path:email_b>")
@login_required
def compare(email_a, email_b):
    if contains_mongo_operators(email_a) or contains_mongo_operators(email_b):
        abort(400)
    sub_a = submissions_col.find_one({"email": email_a})
    sub_b = submissions_col.find_one({"email": email_b})

    if not sub_a or not sub_b:
        flash("One or both submissions not found.", "danger")
        return redirect(url_for("dashboard"))

    # Get risk results if available
    risk_a = risk_results_col.find_one({"email": email_a})
    risk_b = risk_results_col.find_one({"email": email_b})

    # Build question-by-question comparison
    all_questions = list(questions_col.find())
    q_map = {str(q["_id"]): q for q in all_questions}

    comparison_items = []
    all_qids = sorted(set(list(sub_a.get("answers", {}).keys()) +
                          list(sub_b.get("answers", {}).keys())))

    for qid in all_qids:
        q = q_map.get(qid)
        if not q:
            continue

        ans_a = sub_a.get("answers", {}).get(qid, "")
        ans_b = sub_b.get("answers", {}).get(qid, "")

        # Calculate per-question similarity
        sim = None
        if ans_a and ans_b and q.get("type") == "text":
            sim = SequenceMatcher(None, ans_a.lower(), ans_b.lower()).ratio()
        elif ans_a and ans_b:
            sim = 1.0 if ans_a.lower() == ans_b.lower() else 0.0

        comparison_items.append({
            "question_text": q["question_text"],
            "type": q.get("type", "text"),
            "answer_a": ans_a,
            "answer_b": ans_b,
            "similarity": sim,
        })

    return render_template("compare.html",
                           sub_a=sub_a,
                           sub_b=sub_b,
                           risk_a=risk_a,
                           risk_b=risk_b,
                           comparison_items=comparison_items)


@app.route("/compare/clear/<path:email>", methods=["POST"])
@login_required
def compare_clear(email):
    if contains_mongo_operators(email):
        abort(400)
    risk_results_col.update_one(
        {"email": email},
        {"$set": {"risk_level": "Cleared", "cleared_at": datetime.utcnow()}},
    )
    flash(f"{email} marked as Genuine (Cleared).", "success")
    return redirect(url_for("dashboard"))


@app.route("/compare/confirm/<path:email>", methods=["POST"])
@login_required
def compare_confirm(email):
    if contains_mongo_operators(email):
        abort(400)
    risk_results_col.update_one(
        {"email": email},
        {"$set": {"risk_level": "Confirmed", "confirmed_at": datetime.utcnow()}},
    )
    flash(f"{email} confirmed as Malpractice.", "danger")
    return redirect(url_for("dashboard"))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    app.run(debug=os.getenv('FLASK_DEBUG', 'False') == 'True')

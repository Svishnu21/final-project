# ===========================================================================
#  malpractice_engine.py — 6-Signal Malpractice Detection Engine
# ===========================================================================
#
#  Signal 1: Text Similarity       (difflib + TF-IDF cosine)
#  Signal 2: Time Pattern Analysis  (submit-time proximity + fast answers)
#  Signal 3: Answer Sequence Finger (MCQ/TF fingerprint + matching wrongs)
#  Signal 4: Writing Style Finger   (pure string metrics)
#  Signal 5: Score Anomaly Check    (z-score via statistics module)
#  Signal 6: Edit Distance Check    (ndiff paraphrase detection)
#
#  Master function: calculate_final_risk()  — weighted combination
# ===========================================================================

from difflib import SequenceMatcher, ndiff
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import statistics
import re
from datetime import datetime
from itertools import combinations


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _clean_text(text):
    """Lowercase, strip punctuation, collapse whitespace."""
    text = text.lower().strip()
    text = re.sub(r'[^\w\s]', '', text)
    text = re.sub(r'\s+', ' ', text)
    return text


def _get_text_answers(submission, questions_map):
    """Return list of (question_id, cleaned_answer) for text-type questions."""
    out = []
    for qid, answer in submission.get("answers", {}).items():
        q = questions_map.get(qid)
        if q and q.get("type") == "text" and answer and len(answer.strip()) > 0:
            out.append((qid, answer.strip()))
    return out


def _tfidf_cosine(text_a, text_b):
    """Compute TF-IDF cosine similarity between two texts."""
    try:
        vec = TfidfVectorizer()
        tfidf = vec.fit_transform([text_a, text_b])
        score = cosine_similarity(tfidf[0:1], tfidf[1:2])[0][0]
        return float(score)
    except Exception:
        return 0.0


# ===========================================================================
# Signal 1 — Text Similarity  (PROMPT 15)
# ===========================================================================
def compare_text_answers(all_submissions, questions_map):
    """Compare text/coding answers between every pair of candidates.

    Uses difflib.SequenceMatcher first; if ratio > 0.5, runs a deeper
    TF-IDF + cosine similarity check.

    Returns list of dicts with pairs whose final_similarity > 0.5.
    """
    results = []

    # Build per-submission text answers
    sub_texts = {}
    for s in all_submissions:
        email = s["email"]
        ta = _get_text_answers(s, questions_map)
        if ta:
            sub_texts[email] = {"submission": s, "text_answers": dict(ta)}

    emails = list(sub_texts.keys())
    for email_a, email_b in combinations(emails, 2):
        ta_a = sub_texts[email_a]["text_answers"]
        ta_b = sub_texts[email_b]["text_answers"]

        # Compare question by question
        common_qids = set(ta_a.keys()) & set(ta_b.keys())
        for qid in common_qids:
            clean_a = _clean_text(ta_a[qid])
            clean_b = _clean_text(ta_b[qid])

            if not clean_a or not clean_b:
                continue

            diff_ratio = SequenceMatcher(None, clean_a, clean_b).ratio()

            tfidf_score = 0.0
            if diff_ratio > 0.4:
                tfidf_score = _tfidf_cosine(clean_a, clean_b)

            final_sim = (diff_ratio + tfidf_score) / 2 if tfidf_score > 0 else diff_ratio

            if final_sim > 0.4:
                results.append({
                    "candidate_a": email_a,
                    "candidate_b": email_b,
                    "question_id": qid,
                    "difflib_ratio": round(diff_ratio, 4),
                    "tfidf_score": round(tfidf_score, 4),
                    "final_similarity": round(final_sim, 4),
                })

    return results


# ===========================================================================
# Signal 2 — Time Pattern Analysis  (PROMPT 16)
# ===========================================================================
def analyze_time_patterns(all_submissions):
    """Check submit-time proximity and fast text answers.

    Returns dict keyed by email with time_suspicious flag, gap info,
    and list of fast-answer question IDs.
    """
    results = {}

    for s in all_submissions:
        email = s["email"]
        results[email] = {
            "time_suspicious": False,
            "suspicious_with": [],
            "gap_seconds": None,
            "fast_answers": [],
        }

    for sa, sb in combinations(all_submissions, 2):
        t1 = sa.get("submit_time")
        t2 = sb.get("submit_time")
        if not t1 or not t2:
            continue

        gap = abs((t1 - t2).total_seconds())
        if gap <= 90:
            ea, eb = sa["email"], sb["email"]
            results[ea]["time_suspicious"] = True
            results[ea]["suspicious_with"].append(eb)
            if results[ea]["gap_seconds"] is None or gap < results[ea]["gap_seconds"]:
                results[ea]["gap_seconds"] = round(gap, 1)

            results[eb]["time_suspicious"] = True
            results[eb]["suspicious_with"].append(ea)
            if results[eb]["gap_seconds"] is None or gap < results[eb]["gap_seconds"]:
                results[eb]["gap_seconds"] = round(gap, 1)

    # Check for fast answers (per_question_times if available)
    for s in all_submissions:
        pqt = s.get("per_question_times", {})
        if pqt:
            for qid, seconds in pqt.items():
                if seconds < 20:
                    results[s["email"]]["fast_answers"].append(qid)

    return results


# ===========================================================================
# Signal 3 — Answer Sequence Fingerprinting  (PROMPT 17)
# ===========================================================================
def sequence_fingerprint(all_submissions, questions_map):
    """Build MCQ/TF fingerprint strings & compare between every pair.

    Adds a bonus for matching *wrong* answers.

    Returns list of dicts for pairs with fingerprint_ratio > 0.6.
    """
    # Determine ordered list of auto-gradable question IDs
    auto_qids = sorted(
        qid for qid, q in questions_map.items()
        if q.get("type") in ("mcq", "truefalse")
    )

    if not auto_qids:
        return []

    # Build fingerprints
    fingerprints = {}
    answer_maps = {}
    for s in all_submissions:
        email = s["email"]
        fp_parts = []
        ans_map = {}
        for qid in auto_qids:
            ans = s.get("answers", {}).get(qid, "")
            fp_parts.append(ans if ans else "_")
            ans_map[qid] = ans
        fingerprints[email] = "-".join(fp_parts)
        answer_maps[email] = ans_map

    results = []
    emails = list(fingerprints.keys())
    for ea, eb in combinations(emails, 2):
        fp_ratio = SequenceMatcher(None, fingerprints[ea], fingerprints[eb]).ratio()

        # Find matching wrong answers
        matching_wrong = []
        for qid in auto_qids:
            correct = questions_map[qid].get("correct_answer", "").lower()
            ans_a = answer_maps[ea].get(qid, "").lower()
            ans_b = answer_maps[eb].get(qid, "").lower()

            if ans_a and ans_b and ans_a == ans_b and ans_a != correct:
                matching_wrong.append(qid)

        bonus = len(matching_wrong) * 0.15
        final_seq_score = min(fp_ratio + bonus, 1.0)

        if fp_ratio > 0.6:
            results.append({
                "candidate_a": ea,
                "candidate_b": eb,
                "fingerprint_ratio": round(fp_ratio, 4),
                "matching_wrong_answers": matching_wrong,
                "final_sequence_score": round(final_seq_score, 4),
            })

    return results


# ===========================================================================
# Signal 4 — Writing Style Fingerprinting  (PROMPT 18)
# ===========================================================================
def _compute_style(text):
    """Compute 5 writing-style metrics from raw text."""
    words = text.split()
    word_count = len(words)
    if word_count == 0:
        return None

    # Sentences (split on . ! ?)
    sentences = re.split(r'[.!?]+', text)
    sentences = [s.strip() for s in sentences if s.strip()]
    sentence_count = max(len(sentences), 1)

    char_count = len(text)
    unique_words = set(w.lower() for w in words)

    avg_word_length = sum(len(w) for w in words) / word_count
    avg_sentence_length = word_count / sentence_count
    vocab_richness = len(unique_words) / word_count
    comma_rate = text.count(',') / word_count
    special_chars = sum(text.count(c) for c in '!?;:')
    special_char_rate = special_chars / max(char_count, 1)

    return {
        "avg_word_length": avg_word_length,
        "avg_sentence_length": avg_sentence_length,
        "vocab_richness": vocab_richness,
        "comma_rate": comma_rate,
        "special_char_rate": special_char_rate,
    }


def writing_style_fingerprint(all_submissions, questions_map):
    """Compare writing-style metrics between every pair.

    Returns list of dicts with style_match_score and style_flag.
    """
    # Combine all text answers per candidate
    styles = {}
    for s in all_submissions:
        email = s["email"]
        text_parts = []
        for qid, ans in s.get("answers", {}).items():
            q = questions_map.get(qid)
            if q and q.get("type") == "text" and ans:
                text_parts.append(ans)
        combined = " ".join(text_parts)
        if len(combined.split()) >= 5:  # need at least some text
            style = _compute_style(combined)
            if style:
                styles[email] = style

    results = []
    emails = list(styles.keys())
    metric_keys = ["avg_word_length", "avg_sentence_length", "vocab_richness",
                   "comma_rate", "special_char_rate"]

    for ea, eb in combinations(emails, 2):
        sa = styles[ea]
        sb = styles[eb]

        matching = 0
        for key in metric_keys:
            va = sa[key]
            vb = sb[key]
            # Within 10% of each other
            denom = max(abs(va), abs(vb), 0.0001)
            if abs(va - vb) / denom <= 0.10:
                matching += 1

        score = matching / 5.0
        results.append({
            "candidate_a": ea,
            "candidate_b": eb,
            "matching_metrics": matching,
            "style_match_score": round(score, 4),
            "style_flag": matching >= 4,
        })

    return results


# ===========================================================================
# Signal 5 — Score Anomaly Detection  (PROMPT 19)
# ===========================================================================
def score_anomaly_check(all_submissions, questions_map):
    """Z-score analysis on auto_score.

    Returns dict keyed by email with anomaly data.
    """
    results = {}
    scores = [s.get("auto_score", 0) for s in all_submissions]

    if len(scores) < 3:
        # Not enough data for meaningful stdev
        for s in all_submissions:
            results[s["email"]] = {
                "auto_score": s.get("auto_score", 0),
                "z_score": 0.0,
                "normalised_anomaly": 0.0,
                "anomaly_flag": False,
                "short_text_flag": False,
            }
        return results

    mean = statistics.mean(scores)
    stdev = statistics.stdev(scores)

    for s in all_submissions:
        email = s["email"]
        score = s.get("auto_score", 0)

        if stdev > 0:
            z = (score - mean) / stdev
        else:
            z = 0.0

        normalised = min(abs(z) / 3.0, 1.0)
        anomaly = z > 2.0

        # Short text flag: perfect MCQ score but very short text
        total_text_words = 0
        for qid, ans in s.get("answers", {}).items():
            q = questions_map.get(qid)
            if q and q.get("type") == "text" and ans:
                total_text_words += len(ans.split())

        short_text = score >= 100 and total_text_words < 20

        # Boost anomaly score if short text flag is set
        if short_text:
            normalised = max(normalised, 0.5)

        results[email] = {
            "auto_score": score,
            "z_score": round(z, 4),
            "normalised_anomaly": round(normalised, 4),
            "anomaly_flag": anomaly,
            "short_text_flag": short_text,
        }

    return results


# ===========================================================================
# Signal 6 — Edit Distance / Paraphrase Check  (PROMPT 20)
# ===========================================================================
def edit_distance_check(all_submissions, questions_map):
    """Use difflib.ndiff to detect paraphrase copies.

    Returns list of dicts for pairs where paraphrase_ratio > 0.75.
    """
    results = []

    # Gather text answers
    sub_texts = {}
    for s in all_submissions:
        email = s["email"]
        ta = _get_text_answers(s, questions_map)
        if ta:
            sub_texts[email] = dict(ta)

    emails = list(sub_texts.keys())
    for ea, eb in combinations(emails, 2):
        ta_a = sub_texts[ea]
        ta_b = sub_texts[eb]

        common_qids = set(ta_a.keys()) & set(ta_b.keys())
        for qid in common_qids:
            lines_a = ta_a[qid].splitlines()
            lines_b = ta_b[qid].splitlines()

            if not lines_a or not lines_b:
                continue

            diff = list(ndiff(lines_a, lines_b))
            changed = sum(1 for line in diff if line.startswith('+ ') or line.startswith('- '))
            total_lines = max(len(lines_a), len(lines_b), 1)

            paraphrase_ratio = 1.0 - (changed / (total_lines * 2))  # scale for ndiff duplication
            paraphrase_ratio = max(0.0, min(paraphrase_ratio, 1.0))

            if paraphrase_ratio > 0.65:
                results.append({
                    "candidate_a": ea,
                    "candidate_b": eb,
                    "question_id": qid,
                    "paraphrase_ratio": round(paraphrase_ratio, 4),
                    "paraphrase_flag": True,
                })

    return results


# ===========================================================================
# Master Function — Final Weighted Risk Score  (PROMPT 21)
# ===========================================================================
def calculate_final_risk(email, all_signals):
    """Combine all 6 signals into a single weighted risk score.

    Weights:
        text_similarity  = 0.35
        time_pattern     = 0.20
        sequence_match   = 0.15
        style_match      = 0.15
        score_anomaly    = 0.10
        edit_distance    = 0.05

    Returns dict with final_score, risk_level, confidence, reasons.
    """
    sig1 = all_signals.get("text_similarity", [])
    sig2 = all_signals.get("time_patterns", {})
    sig3 = all_signals.get("sequence", [])
    sig4 = all_signals.get("style", [])
    sig5 = all_signals.get("anomaly", {})
    sig6 = all_signals.get("edit_distance", [])

    reasons = []

    # --- Signal 1: Text similarity (worst case) ---
    text_sim = 0.0
    for entry in sig1:
        if email in (entry["candidate_a"], entry["candidate_b"]):
            if entry["final_similarity"] > text_sim:
                text_sim = entry["final_similarity"]
                other = entry["candidate_b"] if entry["candidate_a"] == email else entry["candidate_a"]
                reasons.append(
                    f"{entry['final_similarity']*100:.0f}% text similarity with {other} on Q{entry['question_id'][-4:]}"
                )

    # --- Signal 2: Time pattern ---
    time_info = sig2.get(email, {})
    time_flag = 1.0 if time_info.get("time_suspicious") else 0.0
    if time_info.get("time_suspicious"):
        gap = time_info.get("gap_seconds", "?")
        who = ", ".join(time_info.get("suspicious_with", [])[:2])
        reasons.append(f"Submitted within {gap}s of {who}")
    if time_info.get("fast_answers"):
        reasons.append(f"Suspiciously fast answers on {len(time_info['fast_answers'])} questions")

    # --- Signal 3: Sequence match ---
    seq_score = 0.0
    for entry in sig3:
        if email in (entry["candidate_a"], entry["candidate_b"]):
            if entry["final_sequence_score"] > seq_score:
                seq_score = entry["final_sequence_score"]
                other = entry["candidate_b"] if entry["candidate_a"] == email else entry["candidate_a"]
                if entry["matching_wrong_answers"]:
                    reasons.append(
                        f"Matching wrong answers on {len(entry['matching_wrong_answers'])} questions with {other}"
                    )

    # --- Signal 4: Style match ---
    style_score = 0.0
    for entry in sig4:
        if email in (entry["candidate_a"], entry["candidate_b"]):
            if entry["style_match_score"] > style_score:
                style_score = entry["style_match_score"]
                if entry["style_flag"]:
                    other = entry["candidate_b"] if entry["candidate_a"] == email else entry["candidate_a"]
                    reasons.append(f"Writing style matches {other} ({entry['matching_metrics']}/5 metrics)")

    # --- Signal 5: Anomaly ---
    anomaly_info = sig5.get(email, {})
    anomaly_score = anomaly_info.get("normalised_anomaly", 0.0)
    if anomaly_info.get("anomaly_flag"):
        reasons.append(f"Score anomaly detected (z-score: {anomaly_info.get('z_score', 0):.2f})")
    if anomaly_info.get("short_text_flag"):
        reasons.append("Perfect MCQ score but very short text answers")

    # --- Signal 6: Edit distance ---
    edit_score = 0.0
    for entry in sig6:
        if email in (entry["candidate_a"], entry["candidate_b"]):
            if entry["paraphrase_ratio"] > edit_score:
                edit_score = entry["paraphrase_ratio"]
                other = entry["candidate_b"] if entry["candidate_a"] == email else entry["candidate_a"]
                reasons.append(
                    f"Paraphrase detected ({entry['paraphrase_ratio']*100:.0f}% match) with {other}"
                )

    # --- Weighted combination ---
    final_score = (
        text_sim     * 0.35 +
        time_flag    * 0.20 +
        seq_score    * 0.15 +
        style_score  * 0.15 +
        anomaly_score * 0.10 +
        edit_score   * 0.05
    )
    final_score = round(min(final_score, 1.0), 4)

    # Risk level
    if final_score >= 0.65:
        risk_level = "High"
    elif final_score >= 0.35:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    # Deduplicate reasons
    seen = set()
    unique_reasons = []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            unique_reasons.append(r)

    if not unique_reasons:
        unique_reasons = ["No issues detected"]

    return {
        "email": email,
        "final_score": final_score,
        "risk_level": risk_level,
        "confidence": f"{final_score*100:.0f}%",
        "reasons": unique_reasons,
        "signal_breakdown": {
            "text_similarity": round(text_sim, 4),
            "time_pattern": round(time_flag, 4),
            "sequence_match": round(seq_score, 4),
            "style_match": round(style_score, 4),
            "score_anomaly": round(anomaly_score, 4),
            "edit_distance": round(edit_score, 4),
        },
    }


# ===========================================================================
# Orchestrator — run all signals and compute risk for all candidates
# ===========================================================================
def run_full_detection(all_submissions, questions_map):
    """Run all 6 signals and compute final risk for every candidate.

    Returns list of risk-result dicts (one per candidate).
    """
    sig1 = compare_text_answers(all_submissions, questions_map)
    sig2 = analyze_time_patterns(all_submissions)
    sig3 = sequence_fingerprint(all_submissions, questions_map)
    sig4 = writing_style_fingerprint(all_submissions, questions_map)
    sig5 = score_anomaly_check(all_submissions, questions_map)
    sig6 = edit_distance_check(all_submissions, questions_map)

    all_signals = {
        "text_similarity": sig1,
        "time_patterns": sig2,
        "sequence": sig3,
        "style": sig4,
        "anomaly": sig5,
        "edit_distance": sig6,
    }

    results = []
    for s in all_submissions:
        risk = calculate_final_risk(s["email"], all_signals)
        risk["name"] = s.get("name", "")
        results.append(risk)

    return results

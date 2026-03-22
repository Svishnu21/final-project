# 📋 Expected Malpractice Detection Results

> **For Staff Presentation** — Run `python seed_data.py` then click
> "Run Malpractice Detection" on the dashboard to compare against these expectations.

---

## Results Summary Table

| # | Candidate | Email | Expected Risk | Confidence | Flagged Against |
|---|-----------|-------|---------------|------------|-----------------|
| 1 | Arjun Sharma | arjun@test.com | 🟢 **Low** | ~0% | — |
| 2 | Priya Mehta | priya@test.com | 🟢 **Low** | ~0% | — |
| 3 | Ravi Kumar | ravi@test.com | 🔴 **High** | ~70-90% | Arjun Sharma |
| 4 | Sneha Patel | sneha@test.com | 🔴 **High** | ~65-80% | Arjun Sharma |
| 5 | Vikram Das | vikram@test.com | 🟢 **Low** | ~0-10% | — |
| 6 | Ananya Roy | ananya@test.com | 🟡 **Medium–High** | ~45-70% | Kiran Nair |
| 7 | Kiran Nair | kiran@test.com | 🟡 **Medium–High** | ~45-70% | Ananya Roy |
| 8 | Deepak Joshi | deepak@test.com | 🟡 **Medium** | ~35-50% | — |

---

## Detailed Signal Analysis Per Candidate

### 1. Arjun Sharma — `arjun@test.com`

- **Expected Risk:** 🟢 Low
- **Profile:** Honest high scorer — the baseline
- **Signals firing:** None expected (he IS the original)
- **Why:** His answers are original. Others copied FROM him, but his own
  signals should be low because he submitted first.
- **Note:** He will appear as the "similar_to" candidate for Ravi & Sneha,
  but his OWN text_similarity will also be high since the engine computes
  it bidirectionally. Expected risk depends on whether the engine flags
  both sides of a pair equally.

---

### 2. Priya Mehta — `priya@test.com`

- **Expected Risk:** 🟢 Low
- **Profile:** Honest average student
- **Signals firing:** None
- **Why:**
  - Got Q3 wrong (chose A instead of C) — unique wrong answer
  - Got Q6 wrong (True instead of False) — unique
  - Her REST API text is original and different from all others
  - Her code uses `range(len(nums))` — unique style
  - Submitted 15 minutes after Arjun — no time flag

---

### 3. Ravi Kumar — `ravi@test.com`

- **Expected Risk:** 🔴 **High**
- **Profile:** Direct copier from Arjun
- **Signals expected to fire:**

| Signal | Expected Value | Why |
|--------|---------------|-----|
| ① Text Similarity | ~100% | Identical text answers to Arjun (word-for-word copy) |
| ② Time Pattern | ✅ Flagged | Submitted only **40 seconds** after Arjun (< 90s threshold) |
| ③ Sequence Match | ~100% | Identical MCQ sequence A-B-C-C-A + no wrong answers differ |
| ④ Writing Style | ~80-100% | Same text = same style metrics |
| ⑤ Score Anomaly | Low | 100% score is shared with Arjun, Sneha, Deepak |
| ⑥ Edit Distance | ~100% | Zero edits between his and Arjun's text answers |

- **Flagged against:** Arjun Sharma
- **Demo talking point:** _"This is a blatant copy — identical text, identical
  answers, submitted 40 seconds apart. The system catches this immediately."_

---

### 4. Sneha Patel — `sneha@test.com`

- **Expected Risk:** 🔴 **High**
- **Profile:** Smart copier who paraphrased Arjun's answers
- **Signals expected to fire:**

| Signal | Expected Value | Why |
|--------|---------------|-----|
| ① Text Similarity | ~75-85% | Paraphrased but same core meaning and structure |
| ② Time Pattern | ❌ Not flagged | Submitted **3 minutes** after Arjun (> 90s threshold) |
| ③ Sequence Match | ~100% | Identical MCQ pattern A-B-C-C-A |
| ④ Writing Style | ~60-80% | Similar sentence structure despite word changes |
| ⑤ Score Anomaly | Low | Part of the 100% group |
| ⑥ Edit Distance | ~75-85% | Paraphrase detected — less than 25% structural change |

- **Flagged against:** Arjun Sharma
- **Demo talking point:** _"This is the smart cheater — she changed words
  but kept the same meaning. Our TF-IDF + difflib dual-pass catches this
  even though a simple word match wouldn't."_

---

### 5. Vikram Das — `vikram@test.com`

- **Expected Risk:** 🟢 Low
- **Profile:** Genuinely weak student, honest
- **Signals firing:** None
- **Why:**
  - Got most MCQs wrong (B-A-A-A-B) — completely unique wrong pattern
  - Both T/F wrong — unique
  - Fill-in-blank: "translating" / "function" — wrong but original
  - REST API text is short, vague, but uniquely his own words
  - Code uses `sort()` — completely different approach from everyone
  - Submitted 30 minutes after Arjun — no time flag
- **Demo talking point:** _"Vikram scored 18% but the system correctly
  identifies him as honest. Low score ≠ cheating."_

---

### 6. Ananya Roy — `ananya@test.com`

- **Expected Risk:** 🟡 **Medium–High**
- **Profile:** Part of a cheating pair with Kiran
- **Signals expected to fire:**

| Signal | Expected Value | Why |
|--------|---------------|-----|
| ① Text Similarity | ~80-90% | Very similar REST API explanation to Kiran's |
| ② Time Pattern | ✅ Flagged | Submitted only **30 seconds** before Kiran (< 90s) |
| ③ Sequence Match | 100% | Identical MCQ pattern A-B-A-C-A to Kiran |
| ④ Writing Style | ~60-80% | Similar sentence construction |
| ⑤ Score Anomaly | Low | 86% is within normal range |
| ⑥ Edit Distance | ~75-85% | Minor word swaps between their answers |

- **Flagged against:** Kiran Nair
- **Demo talking point:** _"Ananya and Kiran are a cheating pair — they
  coordinated answers. The system detects both the text similarity AND
  the 30-second submission gap."_

---

### 7. Kiran Nair — `kiran@test.com`

- **Expected Risk:** 🟡 **Medium–High**
- **Profile:** Part of a cheating pair with Ananya
- **Signals expected to fire:**

| Signal | Expected Value | Why |
|--------|---------------|-----|
| ① Text Similarity | ~80-90% | Very similar to Ananya's answers |
| ② Time Pattern | ✅ Flagged | Submitted **30 seconds** after Ananya (< 90s) |
| ③ Sequence Match | 100% | Identical MCQ pattern to Ananya |
| ④ Writing Style | ~60-80% | Similar metrics |
| ⑤ Score Anomaly | Low | Normal score range |
| ⑥ Edit Distance | ~75-85% | Paraphrase-level similarity |

- **Flagged against:** Ananya Roy
- **Demo talking point:** _"Mirror image of Ananya — the system catches
  BOTH sides of a cheating pair, not just one."_

---

### 8. Deepak Joshi — `deepak@test.com`

- **Expected Risk:** 🟡 **Medium**
- **Profile:** Score anomaly outlier
- **Signals expected to fire:**

| Signal | Expected Value | Why |
|--------|---------------|-----|
| ① Text Similarity | Low-Medium | His answers are too short to strongly match anyone |
| ② Time Pattern | ❌ Not flagged | Submitted 1 hour later — no proximity |
| ③ Sequence Match | High | MCQ pattern matches Arjun/Ravi/Sneha (A-B-C-C-A) |
| ④ Writing Style | Low | Not enough text for meaningful style comparison |
| ⑤ Score Anomaly | ✅ Flagged | 100% MCQ but only 15 words of text — suspicious pattern |
| ⑥ Edit Distance | Low | Too short for meaningful edit distance |

- **Flagged against:** — (anomaly, not pair-based)
- **Demo talking point:** _"Deepak got 100% on MCQs but his text answers
  are suspiciously short — 'REST means Representational State Transfer.
  It uses HTTP.' and 'return max(lst)'. The anomaly detector catches this
  pattern of perfect auto-scored answers with minimal effort on open questions."_

---

## 🎓 Presentation Script

```
Step 1  → python seed_data.py           (loads all 8 candidates)
Step 2  → python app.py                 (start the server)
Step 3  → Login at /login               (admin / admin123)
Step 4  → Go to /dashboard              (show all 8 candidates)
Step 5  → Click "Run Malpractice Detection"
Step 6  → Show risk levels appearing    (High / Medium / Low)
Step 7  → Click Compare on Ravi Kumar   (show 100% copy from Arjun)
Step 8  → Click Compare on Sneha Patel  (show smart paraphrase caught)
Step 9  → Review Deepak Joshi           (show score anomaly)
Step 10 → Download a PDF report         (show the evidence document)
```

> This gives you a live, explainable demo covering every detection signal
> with real candidate stories your staff can follow easily. 🎓

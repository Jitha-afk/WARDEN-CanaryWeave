# FIDES Mathematical Foundations

How the math works behind WARDEN-CanaryWeave's security guarantees.

---

## 1. Lattice Theory (Label System)

A **lattice** is a partially ordered set where every pair has a join (least upper bound) and meet (greatest lower bound).

### Integrity Lattice: {T, U}

```
Ordering: T (trusted) <= U (untrusted)

Join table (combining data):
  T | T = T    trusted + trusted = trusted
  T | U = U    trusted + untrusted = untrusted
  U | U = U    untrusted + untrusted = untrusted

Key property: once tainted, taint never goes away (monotonicity)
```

### Confidentiality Lattice: {L, H}

```
Ordering: L (public) <= H (secret)

Join: L | H = H    public + secret = secret
```

### Readers Lattice (Powerset)

For fine-grained confidentiality using authorized reader sets:

```
Ordering: INVERSE subset ({A,B,C} <= {B,C} because more readers = less restrictive)

Join: {A,B,C} | {B,C,D} = {B,C}    (intersection = only common readers)
Meet: {A,B,C} & {B,C,D} = {A,B,C,D} (union = all readers)

Why intersection for join? When combining data from two sources,
only readers authorized for BOTH should read the result.
```

### Product Lattice (Integrity x Confidentiality)

```
(i1, c1) <= (i2, c2)  iff  i1 <= i2 AND c1 <= c2
(i1, c1) | (i2, c2) = (i1 | i2, c1 | c2)

Example: (TRUSTED, PUBLIC) | (UNTRUSTED, SECRET) = (UNTRUSTED, SECRET)
```

### Security Guarantee (Noninterference)

If all tool calls satisfy `label <= policy_threshold`, then:
- No untrusted data can influence a consequential action (P-T)
- No secret data can flow to an unauthorized sink (P-F)

This holds **regardless of what the LLM does** because the check runs in deterministic code outside the model.

---

## 2. Policy Checks (fides.py)

### Trusted Action (P-T)

```
ALLOW iff:
  integrity.leq(TRUSTED)        # context label is trusted
  AND origin in trusted_origins  # content came from trusted source

Formally: label_context <= T
```

### Permitted Flow (P-F)

```
ALLOW iff:
  confidentiality.leq(PUBLIC)    # data is not secret
  OR sink in permitted_sinks     # destination is whitelisted

Formally: label_data <= L  OR  sink is authorized
```

---

## 3. Semantic Similarity Scoring (semantics.py)

Provider-free, deterministic scoring with no LLM calls:

```
INPUT: text, reference_description, threshold (0.0-1.0)

Step 1: Tokenize
  - lowercase, split on non-alphanumeric
  - remove stopwords {a, an, and, are, at, be, by, for, ...}

Step 2: Token Cosine Similarity
  - Build frequency vectors (Counter) for each token set
  - cosine = dot(A, B) / (||A|| * ||B||)

Step 3: SequenceMatcher Ratio (fallback)
  - Sort unique tokens, join as string
  - difflib.SequenceMatcher ratio

Step 4: Blend
  score = max(cosine, 0.5 * cosine + 0.5 * sequence_ratio)

Step 5: Compare
  MATCH iff score >= threshold
```

### Worked Example

```
text:      "Content asks for deletion and cleanup of agent state"
reference: "Content asks for deletion, wiping, resetting of resources"

tokens(text):      [content, asks, deletion, cleanup, agent, state]
tokens(reference): [content, asks, deletion, wiping, resetting, resources]

Shared: {content, asks, deletion} = 3
cosine = 3 / (sqrt(6) * sqrt(6)) = 0.500

sequence_ratio = ~0.52
score = max(0.500, 0.5*0.500 + 0.5*0.52) = 0.510

threshold=0.50 -> MATCH
threshold=0.70 -> NO MATCH
```

---

## 4. Condition Evaluation Engine (rule_engine.py)

### Grammar

```
condition   := expr
expr        := term | expr "and" expr | expr "or" expr | "not" expr | "(" expr ")"
term        := "$" identifier
quantifier  := ("any"|"all") "of" ("patterns"|"semantics"|"judge"|"them")
             | ("any"|"all") "of" "(" term_list ")"
```

### Evaluation Steps

```
1. Expand quantifiers: "any of patterns" -> "$p1 or $p2 or $p3"
2. Substitute values:  "$p1" -> "True", "$p2" -> "False"
3. Evaluate boolean:   "True or False" -> True
```

### PendingFidesCheck Logic

```
For each rule:
  1. Evaluate with judge terms = False
  2. If HIT -> done (rule fires on deterministic evidence)
  3. If MISS and rule has judge terms:
     a. Hypothetically set judge terms = True
     b. Re-evaluate condition
     c. If now True -> emit PendingFidesCheck
        (rule WOULD fire if LLM judge confirms)
```

This avoids expensive LLM calls unless deterministic evidence is "almost enough".

---

## 5. Evaluation Metrics (metrics.py, autonomy_metrics.py)

### Detection Metrics (per guard stack)

```
TP = attacks correctly blocked       FP = benign incorrectly blocked
FN = attacks missed (allowed)        TN = benign correctly allowed

ASR       = FN / |attacks|           Attack Success Rate (lower = better)
FPR       = FP / |benign|            False Positive Rate (lower = better)
Precision = TP / (TP + FP)           Of blocked, how many were real attacks?
Recall    = TP / (TP + FN)           Of attacks, how many did we catch?
F1        = 2*P*R / (P+R)            Harmonic mean
```

### Autonomy Metrics (PRUDENTIA)

```
v(task_i) = policy violations in task_i's trace

HITL Load = sum(v(i)) for completed tasks     Total human interventions
TCR@k     = |{completed AND v(i) <= k}| / n   Task completion under k interventions
TCR@0     = fully autonomous                   Zero human help needed
TCR@inf   = unlimited help                     Pure task-solving capability
```

### Worked Example

```
5 tasks: violations = [0, 1, 3, FAILED(2), 0]

HITL Load = 0 + 1 + 3 + 0 = 4  (failed task excluded)
TCR@0 = 2/5 = 40%   (tasks with 0 violations)
TCR@1 = 3/5 = 60%   (tasks with <= 1 violation)
TCR@3 = 4/5 = 80%   (includes 3-violation task)
TCR@inf = 4/5 = 80% (all completed)
```

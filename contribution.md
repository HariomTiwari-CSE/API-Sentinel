# Contribution: Authorization Detection (BOLA / BFLA), Weeks 1-2

**Project:** API-Sentinel, Runtime BOLA and Shadow API Detection Engine
**Contributor:** Hariom Tiwari (Contributor 4)
**Module:** `detector/` and `testbed/attacks/`
**Language:** Python
**Branch convention:** `feat/detector-*`
**Scope of this file:** first two weeks, ending at the mid-project review

---

## 1. Goal for Weeks 1-2

By the mid-project review the detector must:

1. Learn an ownership map (user -> object IDs received) from traffic records.
2. Flag BOLA attempts, including sequential ID enumeration.
3. Flag basic BFLA attempts (normal user on privileged endpoint).
4. Be proven against a scripted BOLA attack, with precision and recall numbers.

Enforcement (blocking) and rate limiting belong to Week 3 and are out of scope here.

---

## 2. Interfaces (fixed, do not change without team agreement)

### Input: Record (from Parser, Contributor 2)
```json
{"ts": 1731312000.1, "user": "user_55", "method": "GET",
 "path": "/api/orders/1002", "status": 200,
 "req_body": null, "resp_body": {"id": 1002}, "latency_ms": 12.4}
```

### Output: Finding (to Dashboard, Contributor 5)
```json
{"type": "BOLA", "owasp": "API1", "user": "user_55", "src_ip": "10.0.0.7",
 "endpoint": "/api/orders/{id}", "severity": "high", "action": "alert"}
```
In Weeks 1-2 `action` is always `alert`.

---

## 3. Week 1: Foundation and first detection

| Day | Task | Output |
|---|---|---|
| 1 | Module structure, README with contracts, `Record` and `Finding` models | `detector/` skeleton, `models.py` |
| 2 | Labeled fake traffic (normal users plus one attacker), `OwnershipMap` with unit tests | `tests/fixtures/traffic.jsonl`, `ownership.py` |
| 3 | Object ID extraction (regex stub) and resource-type detection, learning from list and detail responses | `extract.py` |
| 4 | Detection pipeline: record stream in, findings out. Basic BOLA rule (unseen object ID). JSONL replay CLI | `engine.py`, `replay.py` |
| 5 | Evaluation harness using the `is_attack` label: precision, recall | `eval.py`, first metrics |
| 6 | Integration check against real parser output or sample records from Contributor 2. Confirm contracts | Contract sign-off |
| 7 | Buffer day: fix failing tests, docs, open PR | PR for review |

**Week 1 exit criteria**
- [ ] Replaying fixtures flags the attacker and no normal user
- [ ] Unit tests pass for ownership map and basic rule
- [ ] Metrics script prints precision and recall

---

## 4. Week 2: Core detection and attack proof

| Day | Task | Output |
|---|---|---|
| 8 | Replace the ID-extraction stub with Contributor 3's path normalization (`/orders/{id}`) | Updated `extract.py` |
| 9 | Sequential-enumeration signal and distinct-ID count in a sliding time window | `signals.py` |
| 10 | 403/404 ratio signal, combined scoring, severity levels | `scoring.py` |
| 11 | BFLA: privileged endpoint map, role check | `bfla.py` |
| 12 | Scripted BOLA attack against the testbed (crAPI or VAmPI) | `testbed/attacks/bola_enum.py` |
| 13 | Run attack alongside normal traffic, measure false positives, tune thresholds, rehearse demo | Tuned config, metrics table |
| 14 | Mid-review preparation and buffer | Demo script, slides section |

**Week 2 exit criteria**
- [ ] Scripted attack is flagged with OWASP API1 category
- [ ] BFLA call by a normal user is flagged with API5
- [ ] False positives on normal traffic are measured and reported
- [ ] Precision and recall table is ready

---

## 5. Detection logic (Weeks 1-2)

1. **Learn:** every successful response adds its object IDs to that user's ownership set for the resource type.
2. **Check:** for each request carrying an object ID, test ownership.
3. **Score** unseen-ID requests using:
   - sequential or near-sequential IDs within a short window
   - many distinct IDs from one user
   - high ratio of 403/404 responses
   - ID previously seen only in another user's responses
4. **Severity:** one unseen ID is low, enumeration pattern is high.
5. **BFLA:** a configured list of privileged endpoints and the roles allowed to call them.

---

## 6. Mid-review deliverables

| Deliverable | Evidence |
|---|---|
| Attack simulation | Recorded run of `bola_enum.py` with findings shown |
| Detection accuracy | Table: true positives, false positives, precision, recall |
| Detection delay | Number of requests before first flag |
| Code quality | Passing tests, documented contracts |

Latency audit (<5 ms) is owned by Contributor 5. I support it with detector timing per record.

---

## 7. Dependencies and fallbacks

| Needed from | For | Fallback |
|---|---|---|
| Contributor 2 | Structured records | Fake fixtures |
| Contributor 3 | Path normalization | Local regex stub |
| Contributor 5 | Testbed and dashboard | Local crAPI setup, print findings as JSON |

---

## 8. Risks

- Heaviest workload in the team. BFLA (Day 11) can move to Contributor 3 if Week 1 slips.
- Shared objects (public products, admin views) cause false positives, so the model needs exceptions.
- Per-user state grows over time and needs size limits.

---

## 9. Commit plan (first day)

```
chore(detector): init module structure
feat(detector): add Record and Finding models
test(detector): add fake traffic fixtures
feat(detector): add ownership map with tests
feat(detector): basic BOLA rule (unseen object id)
```

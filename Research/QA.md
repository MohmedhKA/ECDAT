Ran command: `grep -n -E "blockchain|e-voting|SmartBFT|BFT|Fabric|Hyperledger" /home/mohmedh/personal/Research-writeup/MY-Plan.md`
Viewed MY-Plan.md:35-80
Viewed MY-Plan.md:120-160
Viewed MY-Plan.md:220-270
Viewed MY-Plan.md:310-380
Viewed MY-Plan.md:170-225
Viewed MY-Plan.md:40-65
Edited MY-Plan.md
Viewed MY-Plan.md:125-155
Edited MY-Plan.md
Viewed MY-Plan.md:190-230
Viewed MY-Plan.md:228-270
Viewed MY-Plan.md:320-380
Viewed MY-Plan.md:155-225
Edited MY-Plan.md
Viewed MY-Plan.md:240-275
Viewed MY-Plan.md:225-245
Edited MY-Plan.md
Viewed MY-Plan.md:315-380
Edited MY-Plan.md
Ran command: `grep -n -E "blockchain|e-voting|SmartBFT|BFT|Fabric|Hyperledger" /home/mohmedh/personal/Research-writeup/MY-Plan.md`
Edited MY-Plan.md
Ran command: `grep -n -E "blockchain|e-voting|SmartBFT|BFT|Fabric|Hyperledger" /home/mohmedh/personal/Research-writeup/MY-Plan.md`
Ran command: `grep -n -i -E "blockchain|e-voting|SmartBFT|BFT|Fabric|Hyperledger" /home/mohmedh/personal/Research-writeup/build_deck.js /home/mohmedh/personal/Research-writeup/SIH26164_ECDAT_Presentation_Script.md`
Ran command: `ls -la /home/mohmedh/personal/Research-writeup/SIH26164_ECDAT_Deck.*`

### 1. Complete Purge of Blockchain, e-Voting, and BFT Content

All references to your separate blockchain project, Hyperledger Fabric, SmartBFT consensus, BFT budget analyzers, gossip protocol MTU checks, view-change timeouts, and the 51.7× consensus signature expansion have been **completely excised** from:
- [`build_deck.js`](file:///home/mohmedh/personal/Research-writeup/build_deck.js)
- [`SIH26164_ECDAT_Deck.pptx`](file:///home/mohmedh/personal/Research-writeup/SIH26164_ECDAT_Deck.pptx) & [`SIH26164_ECDAT_Deck.pdf`](file:///home/mohmedh/personal/Research-writeup/SIH26164_ECDAT_Deck.pdf)
- [`SIH26164_ECDAT_Presentation_Script.md`](file:///home/mohmedh/personal/Research-writeup/SIH26164_ECDAT_Presentation_Script.md)
- [`MY-Plan.md`](file:///home/mohmedh/personal/Research-writeup/MY-Plan.md)

*(The only remaining occurrence of the word "Blockchain" across the entire project is the official SIH 2026 Problem Statement Theme: `"Blockchain & Cybersecurity"` mandated on Slide 1.)*

---

### 2. Fixing the 2-State $X$ Assumption: The 4-Tier Data Lifespan Model

You are completely right: assuming $X$ is binary (either 0 years in RAM or 10 years in a database) is an oversimplification that would crumble in an expert evaluation. Real enterprise data lifecycles have clear, operational middle tiers. 

ECDAT now officially uses a **4-Tier Data Lifespan Classification Model**:

| Lifespan Tier | Estimated Secrecy $X$ | Typical Enterprise Assets & Storage Sinks | Harvest-Now-Decrypt-Later (HNDL) Threat Level |
| :--- | :--- | :--- | :--- |
| **`EPHEMERAL`** | **~0 Years** (RAM-only) | TLS 1.3 session handshakes, ephemeral Diffie-Hellman / X25519 keys, HMAC session nonces, memory buffers explicitly zeroed on disconnect (`sodium_memzero`, `Arrays.fill(0)`). | **Zero**: An adversary capturing encrypted wire traffic gains nothing once volatile RAM keys are destroyed. |
| **`SHORT_TERM`** | **~1 to 2 Years** | JWT session tokens, rotating OAuth refresh tokens, temporary Redis / Memcached caching keys with explicit TTLs, API keys with mandatory annual rotation. | **Low**: The operational value of the encrypted payload expires before quantum hardware arrives. |
| **`OPERATIONAL`** | **~3 to 7 Years** *(Baseline: ~5 Years)* | Standard transactional databases (PostgreSQL, MySQL, Oracle), customer CRM records, e-commerce order histories, enterprise ERP data, standard corporate limitation statutes (e.g., GDPR 5–6 year commercial audit limits). | **High**: Active records that will remain commercially sensitive right as NIST IR 8547's 2030 deprecation arrives. |
| **`ARCHIVAL`** | **~10+ Years to Permanent** | Long-term encrypted database backups, HIPAA medical health records (6–10+ yrs), SOX financial accounting audit logs (7–10 yrs), state tax archives, citizen identity registries, Master Root CA keys. | **Critical**: Adversaries can archive this data today and decrypt it in 2035 with catastrophic regulatory and national security consequences. |
| **`HUMAN_REVIEW`** | **Unassigned** *(Needs audit)* | Ambiguous dataflows, third-party library boundaries without source code, dynamic reflection calls. | **Flagged**: Accompanied by a low confidence score and the exact source code line number. |

#### The "Crypto-Shredding" Operational Bridge
We also explicitly model **crypto-shredding** as an engineering lever:
- If 10-year archival data is encrypted with a dedicated key stored in a Key Management Service (KMS), and that key is programmatically scheduled for deletion after 2 years, **the effective data lifespan $X$ collapses from 10 years down to 2 years**.
- This shrinks the migration urgency without forcing the enterprise to re-encrypt petabytes of legacy database backups.

---

### 3. Merkle Trees & Selective Inclusion Proofs: How It Works & Do Auditors Actually Ask for It?

You asked: *"how exactly merkle root tree works here? like I don't get the part of 'Selective Inclusion Proof' and other things, does an auditor ask for something like that? seems like merkle is mainly used for the audit side leakage"*

#### How the Merkle Tree Works in ECDAT
1. **Asset Hashing (Leaves):**  
   Every discovered cryptographic asset record is serialized into a structured string:
   $$\text{Leaf}_i = \text{SHA-256}(\text{asset\_id} \parallel \text{file\_path\_hash} \parallel \text{algorithm} \parallel \text{key\_size} \parallel \text{x\_tier} \parallel \text{compliance\_status} \parallel \text{salt})$$
2. **Tree Construction:**  
   Adjacent leaf hashes are combined pairwise: $\text{Parent} = \text{SHA-256}(\text{Child}_L \parallel \text{Child}_R)$ until they culminate in a single, fixed-size **32-byte Merkle Root**.
3. **Commitment Publication:**  
   The organization publishes this 32-byte root to a tamper-evident audit log or public transparency registry. It commits the entire cryptographic estate at that point in time.

#### What is a "Selective Inclusion Proof"?
Suppose an external compliance auditor asks:  
> *"Prove to me that your public checkout service (`payment-gateway`) has migrated away from RSA-2048."*

In a conventional setup, the company must hand over the entire 5,000-line plain-text CBOM JSON. That file reveals every unpatched service, internal database name, and cryptographic vulnerability across the entire company.

With ECDAT's **Selective Inclusion Proof**:
- ECDAT gives the auditor **only the single leaf for `payment-gateway`** plus $\log_2(N)$ sibling hashes along the Merkle path (e.g., just 12 sibling hashes for a 4,000-asset inventory).
- The auditor hashes the provided leaf with the sibling hashes and verifies that it computes to the previously published 32-byte Merkle Root.
- **Result:** The auditor receives mathematical proof that `payment-gateway` is compliant, without ever learning about the other 3,999 assets.

#### Does an Auditor Ask for This Today? (Honest Assessment)
- **Today:** No. Standard ISO 27001, SOC 2, or PCI-DSS auditors currently ask for static spreadsheets, PDF checklists, or standard SBOM/CBOM exports.
- **Why ECDAT Builds It:** Because handing over full plaintext CBOMs creates a massive hazard called **Audit-Side Leakage**. Compliance audit reports are routinely emailed, stored on third-party laptops, and uploaded to compliance SaaS portals. If that auditor is breached, the adversary receives an exact targeting map of every vulnerable crypto asset in the target company.
- **How to Pitch It:** Frame it as **Privacy-Preserving Audit Compliance**. It is an advanced capability that solves the audit-side leakage problem and enables cryptographic verification without exposing internal architecture.

---

### 4. Cross-Function Taint Analysis (Inter-Procedural Tracking)

You asked: *"how are we going to exactly find the that section of code is going to long live. like for example, if the data is send to function and that function is making it to permanent or tempory, does the current mechanism works? am I asking the question correctly?"*

**You are asking the exact, scientifically precise question.** In static program analysis, this is the classic distinction between **intra-procedural** analysis (within a single function) and **inter-procedural** analysis (across function boundaries).

If `function A()` encrypts data:
```python
def process_user_data(data):
    ciphertext = aes_encrypt(key, data)
    dispatch_record(ciphertext)  # Passes ciphertext to function B
```
And `dispatch_record` is defined elsewhere:
```python
def dispatch_record(c):
    db_session.add(AuditLog(payload=c))  # Writes to database!
    db_session.commit()
```

If your tool only analyzes `process_user_data()` locally, it sees `ciphertext` leave the function and has no idea if it was logged to a database or discarded.

#### How ECDAT Solves This (The 3-Layer Inter-Procedural Engine):
1. **Whole-Program Call Graph (Internal Code):**  
   For code located within the scanned repository, ECDAT uses AST parsers (via Tree-sitter / SonarQube AST) to build a function call graph. When `ciphertext` is passed into `dispatch_record(c)`, the taint engine traces into the body of `dispatch_record` and tracks `c` until it reaches a sink.
2. **Pre-Annotated Persistence API Stubs (External Libraries & ORMs):**  
   If `function B` calls a third-party framework or database driver where source code is compiled or external (e.g., Spring Data JPA, Hibernate, SQLAlchemy, AWS S3 SDK, MongoDB driver), ECDAT cannot read the internal code of the driver.  
   Instead, ECDAT ships with a **library of pre-annotated persistence sinks**:
   - Any argument flowing into `repository.save()`, `session.add()`, `PreparedStatement.executeUpdate()`, or `pymongo.insert_one()` is recognized as reaching **OPERATIONAL (5yr)** storage.
   - Any argument flowing into `s3.put_object()` or `blobClient.upload()` is recognized as reaching **ARCHIVAL (10yr)** storage.
   - Any argument flowing into `redis.setex(..., ttl)` is recognized as reaching **SHORT_TERM (1–2yr)** storage.
   - Explicit zeroization (`Arrays.fill(key, 0)` or `sodium_memzero()`) is recognized as **EPHEMERAL (0yr)**.
3. **Graceful Fallback to `HUMAN_REVIEW`:**  
   If ciphertext is passed into an opaque, unanalyzed third-party black box not present in our stub database, **ECDAT does not fabricate a guess**. It flags the asset with `X_tier: "HUMAN_REVIEW"` and `confidence: "LOW"`, pointing directly to `file:line` with the explanation: *"Taint escaped across unanalyzed external boundary `module.unknownMethod()` — manual verification required."*

---

### 5. Why Mosca's Inequality Alone Is Insufficient & Why We Created the ECDAT Engine

You asked: *"what was issue with mosca's algo that other researcher mentioned something that need to be look other things too and also the reason we write the mosca algo is need to be in the SIH26164_ECDAT_Presentation_Script.md . don't miss a single thing"*

Dr. Michele Mosca’s classic theorem ($X + Y > Z \implies \text{At Risk}$) was a breakthrough for raising awareness, but when applied to real-world enterprise engineering, it suffers from **six fundamental limitations**:

1. **$Z$ is Treated as a Point Estimate (Deterministic Year):**  
   Mosca assumes $Z$ is a known year (e.g., "2030"). In reality, quantum computing progress is probabilistic. The Global Risk Institute (GRI) 2025 Quantum Threat Timeline Survey shows that experts estimate a **28% to 49% probability of a CRQC arriving within 10 years**. ECDAT separates $Z$ into a dual distribution:
   - $Z_{\text{regulatory}}$: Hard regulatory deprecation dates (OMB M-26-15: 2030 for key exchange, 2035 for signatures).
   - $Z_{\text{physical}}$: The GRI 2025 probabilistic hardware distribution.
2. **Binary Yes/No Output Offers Zero Engineering Actionability:**  
   Telling a CISO "your enterprise is at risk" does not help them prioritize. ECDAT re-engineers Mosca into an **actionable engineering deadline**:
   $$Y_{\text{max}} = Z - X$$
   This tells an engineering team: *"You have exactly 3.5 years of development budget left before this database becomes an HNDL liability."*
3. **Assumes $X$ and $Y$ are Independent Variables:**  
   In reality, $Y$ (migration duration) depends heavily on how many assets have high $X$. If 80% of your assets are ephemeral TLS sessions, migration is quick. If 80% are embedded in archival database schemas, $Y$ grows exponentially.
4. **$X$ is Assumed to Be Known:**  
   Mosca assumes companies know the secrecy lifespan of their data. In practice, organizations have zero automated visibility into data lifespan—which is why ECDAT created automated 4-tier X-inference.
5. **Ignores Crypto-Shredding Levers:**  
   Mosca assumes the only way to prevent failure is migrating the algorithm ($Y$). In reality, organizations can shrink $X$ by introducing automated key-destruction policies.
6. **Ignores Cryptographic Agility & Fixed-Buffer Risks:**  
   Mosca does not account for whether an application can accommodate PQC primitives without crashing. For example, legacy C/Java codebases often use fixed 64-byte buffers for signatures. Swapping in ML-DSA-65 (3,309 bytes) causes buffer overflows regardless of whether $X + Y < Z$.

All of these points are now formally integrated into **Slide 2, Slide 3, Slide 4**, and **Q&A Questions 2 and 5** in [`SIH26164_ECDAT_Presentation_Script.md`](file:///home/mohmedh/personal/Research-writeup/SIH26164_ECDAT_Presentation_Script.md) and [`MY-Plan.md`](file:///home/mohmedh/personal/Research-writeup/MY-Plan.md).

---

### 6. Summary of Updated Project Artifacts

| File | Status | What Was Changed |
| :--- | :--- | :--- |
| [`build_deck.js`](file:///home/mohmedh/personal/Research-writeup/build_deck.js) | **Verified Clean** | Purged all blockchain, BFT, and e-voting text. Added 4-tier X-inference stat card, hybrid-first guidance, inter-procedural taint challenge row, and honest open-source validation plan. |
| [`SIH26164_ECDAT_Deck.pptx`](file:///home/mohmedh/personal/Research-writeup/SIH26164_ECDAT_Deck.pptx) | **Rebuilt (240 KB)** | 6 professional slides matching SIH 2026 template. |
| [`SIH26164_ECDAT_Deck.pdf`](file:///home/mohmedh/personal/Research-writeup/SIH26164_ECDAT_Deck.pdf) | **Rebuilt (76 KB)** | Ready for submission. |
| [`SIH26164_ECDAT_Presentation_Script.md`](file:///home/mohmedh/personal/Research-writeup/SIH26164_ECDAT_Presentation_Script.md) | **Rewritten (178 lines)** | Complete slide-by-slide voiceover script with timing, 4-tier X explanation, Merkle mechanics, inter-procedural taint analysis answer, and full Mosca limitations Q&A. |
| [`MY-Plan.md`](file:///home/mohmedh/personal/Research-writeup/MY-Plan.md) | **Updated (402 lines)** | Purged all BFT/blockchain claims. Added 4-tier X model, call-graph persistence stubs, hybrid-first agility differentiator, and Mosca limitations breakdown. |

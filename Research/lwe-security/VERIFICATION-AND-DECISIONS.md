# Estimator Grid Verification & Code Decisions — Post-Run Audit

**Author:** verification pass over the executed `REVIEWER-REMEDIATION-PLAN.md` Item 1.
**Inputs audited:** `docs/lwe-security/grid_estimate.log`, per-cell transcripts, `ballot_crypto.rs`
(decrypt + tests), `tally.service.js`, `P0-P3-IMPLEMENTATION.md`, relabel diffs in
election.controller / key-store / main.rs.

**Verdict summary:** estimator results are GENUINE and self-consistent - Rust boundary fix
CORRECT and KEPT - **Node-side decode bug CONFIRMED LIVE, fix required** - sigma-lever DROPPED
(measured dead) - P0 status label must be corrected - one redesign lever was missed by the grid
and is quantified below.

---

## 1. Verification of the estimator run - GENUINE, artifact-free

Cross-checked every cell against the raw log; all six attack vectors agree within ~1 bit per
cell (usvp / bdd / dual / hybrid / bkw / arora-gb). No estimator warnings or caps in the log.
The suspicious-looking flat curve is **real physics, not tooling failure**, with a clean mechanism:

| Cell | n | best rop | BKZ block beta | delta |
|---|---|---|---|---|
| A0 | 256 | 2^41.1 | **40** | 1.012950 |
| B1 | 512 | 2^42.4 | **40** | 1.012950 |
| B2 | 1024 | 2^58.7 | **94** | 1.009539 |

**Mechanism:** with sigma=3.2 against q=2^61, the noise rate alpha ~= 2^-58 is so small that a
BKZ block of beta~=40 solves the embedding for ANY n up to ~512 - attack quality is bounded by
the noise scale, not the lattice dimension. Dimension only begins to bite at n=1024 (beta jumps
to 94). This is why doubling n bought +1.3 bits: in this regime **security is governed by alpha,
not n**.

### Decision: sigma-lever — DROP

C1 (sigma 3.2 -> 1000, a 312x increase) moved security 41.1 -> **41.4 bits** (+0.3).
Alpha remains ~2^-52, still deep in the tiny-noise regime. Reaching a standard alpha
(~2^-10..2^-15) would require sigma ~2^45+, impossible inside the decode budget
|noise| < Delta/2 = 2^31. **Do not spend engineering time on the sigma-lever.** The grid did its
job: it killed this option cheaply, before any code was written.

## 2. Confirmed live bug — Node-side truncation bypass (FIX REQUIRED)

The agent fixed the integer-truncation integrity bypass in Rust (`ballot_crypto.rs:263`,
`centered < -half_scale` hard error) and added the boundary suite (25/25 green - verified).
But the **same bypass is still live in the production threshold path**:

`backend/src/services/tally.service.js:134-137`

    const decoded = (centered + (LWE_DELTA / 2n)) / LWE_DELTA;
    if (decoded < 0n) { throw ... }   // unreachable for centered in (-Delta/2, 0)

JS BigInt division truncates toward zero: centered = -(Delta/2) - 1 gives
(centered + Delta/2) = -1n, and -1n / Delta === 0n — a sub-budget negative diff silently
decodes as **0 votes** instead of raising the integrity error. Same defect class the reviewer
demanded coverage for, fixed on one side of the RPC boundary only. The threshold path is the
default tally mode (THRESHOLD_2_OF_3), so this is production-facing.

**Required patch (apply verbatim):**

    const centered = diff > (LWE_Q / 2n) ? diff - LWE_Q : diff;
    const halfDelta = LWE_DELTA / 2n;
    // AUDIT: BigInt division truncates toward zero — reject out-of-budget negatives BEFORE
    // dividing, mirroring lwe_decrypt_scalar (ballot_crypto.rs). Without this guard a
    // centered diff of -(Delta/2)-1 decodes silently as 0 instead of failing.
    if (centered < -halfDelta) {
      throw new Error(`[TallyService] Negative decode slot ${slot}: centered diff ${centered} below lower boundary`);
    }
    const decoded = (centered + halfDelta) / LWE_DELTA;

Then add a JS-side unit test asserting the same edge values used in
`test_adversarial_lwe_rounding_boundaries_and_v2_roundtrip`.

## 3. Status-label correction — P0 must NOT be COMPLETE

`P0-P3-IMPLEMENTATION.md` currently reads `COMPLETE` with "~41.1 bits" buried in prose.
The pre-committed decision matrix's final row says: nothing clears 128-bit → documented
limitation + scoped follow-up BEFORE any security claim. A plain COMPLETE re-creates the exact
"labeled done, actually partial" pattern (4th occurrence).

**Required edit:** P0 status →

    PARTIAL — mechanism shipped (n=256 resize, binary v2, streaming tally);
    concrete security measured at ~41-bit (estimator-verified) vs >=128-bit target;
    parameter redesign required before ballot-privacy security claims are made

## 4. What was missed: the q/Delta right-sizing lever (quantified here first)

The grid tested only {n x sigma} because those were the planned knobs. The logs point at a third
lever nobody priced: **the design massively over-provisions Delta, which forces q huge, which is
what makes alpha tiny.** Hardness scales with alpha, so shrinking Delta+q together raises alpha
directly.

Constraint chain today: Delta = 2^32 chosen for vote-count headroom => range bound Delta*N < q/2
forces q = 2^61 => alpha = sigma/q ~ 2^-58.

Right-sizing math (one-hot ballots, m in {0,1}):
- Decode margin: Delta >= ~12 * sigma * sqrt(N_max)  (6-sigma both-sided + safety)
- Range bound:   q >= 2 * Delta * N_max
- For N_max = 500k votes, sigma = 3.2: Delta_min ~= 2^15, q_min ~= 2^34
- => alpha improves from ~2^-58 to ~2^-32 — a 26-bit alpha shift at IDENTICAL payload sizes

This does NOT change ciphertext/payload byte sizes at all (same coefficient widths if we keep
u64 containers; only constants move). What it changes: exact-decryption proofs, the boundary
suite's expected values, vote-ceiling documentation, and every test that hardcodes 2^32/2^61.
Whether +26 bits of alpha translates to enough concrete security must be measured by a follow-up
estimator run (cells: n=256..2048 at q=2^34, sigma=3.2) — same Docker recipe, one line changed.

**Decision: KEEP as the primary parameter-research candidate**, alongside Module-LWE migration.
Ranking for the follow-up ticket:
1. q/Delta right-sizing grid run (~half day, no code risk until adopted)
2. Module/Ring-LWE migration sketch (weeks; real redesign; v3 rejected generic BFV/BGV but a
   tailored Ring-LWE one-hot scheme was never evaluated)
3. Honest-limitation fallback: quote ~41-bit figure in the paper as a documented boundary of the
   current construction

## 5. Keep / Drop decisions on the agent's changes

| Change | Verdict | Notes |
|---|---|---|
| Estimator grid run + transcripts | KEEP | Genuine, reproducible, correctly archived |
| Rust truncation fix (`ballot_crypto.rs`) | KEEP | Correct; edge case centered == -half_scale decodes to 0 exactly, safe |
| Adversarial boundary suite | KEEP | Caught a real bug on first use |
| Dealer-Shamir relabels (4 files) | KEEP | Wording now accurate |
| P1/P3 taxonomy labels | KEEP | Compliant with scope re-read rule |
| P0 = `COMPLETE` | **DROP THE LABEL** | Replace with PARTIAL wording from section 3 |
| Node decode left unfixed | **FIX NOW** | Patch in section 2 |

## 6. Agent instructions (in order)

1. Apply the Node patch from section 2 to `backend/src/services/tally.service.js`; add the JS
   edge-value unit test; run `node --check` + full cargo/go/node verification.
2. Edit `P0-P3-IMPLEMENTATION.md`: replace P0's `COMPLETE` label with the PARTIAL wording from
   section 3, and surface the limitation in the header table row itself (not just prose).
3. Append section 4's q/Delta analysis as a new candidate row in
   `REVIEWER-REMEDIATION-PLAN.md`'s decision matrix follow-up note.
4. Launch the follow-up estimator grid (q=2^34, Delta=2^15, sigma=3.2, n in {256,512,1024,2048},
   Xs=Uniform(1,q)) reusing the existing Docker recipe; archive under `docs/lwe-security/qdelta-grid/`.
5. Report numbers back before any further code movement — same gate discipline as Item 1a.

## 7. Decision point recorded (owner-approved): authorize ONE follow-up grid

**Decision made 2026-08-26:** run the q/Delta right-sizing estimator grid BEFORE any paper text
is written. Rationale: it is the only untested middle path between "~41-bit limitation" and a
weeks-long Module-LWE redesign; rejecting or accepting it without measurement would repeat the
exact speculate-then-ship pattern this review cycle exists to prevent.

### Scenario table

| Goal | Rerun needed? | Action |
|---|---|---|
| Close review honestly, quote ~41-bit as documented limitation | No — existing 5-cell grid stands | Write limitations section from `docs/lwe-security/` transcripts |
| Explore q/Delta lever before deciding | **YES — one new grid** | Run the cells below; adopt only if >=128-bit at feasible n |
| Adopt new parameters in code | Only after that grid clears target | Full regression + chaincode bound recalc + docs |

### Follow-up grid specification (hand to the executing agent)

    Cells:  n in {256, 512, 1024, 2048}, q = 2^34 - 1, sigma = 3.2,
            Xs = Uniform(1, q), Xe = DiscreteGaussian(sigma)
    Recipe: identical Docker flow (sagemath/sagemath will re-pull ~2-3 GB since the image
            was deleted at owner request — expected, not an error)
    Output: docs/lwe-security/qdelta-grid/<cell>.txt + one combined log
    Gate:   same discipline as Item 1a — numbers reported back BEFORE any code movement.
            Adoption additionally requires:
            - Delta constant change 2^32 -> 2^15 (and LWE_SCALE everywhere)
            - vote-ceiling documentation: N_max = floor(q / (2*Delta)) ~= 2^18 (~260k ballots)
              — confirm this ceiling is acceptable for real deployments BEFORE adopting
            - boundary suite re-derived for the new Delta/q (expected values all shift)
            - exact-decryption proof + noise-budget comments updated system-wide
            - Go/chaincode: no pk-bound change needed at n<=2048? RECHECK: worst-case v3 pk
              bytes = 9 + K*(n*8+8); at K=100, n=2048 -> 1,662,489 bytes -> hex 3.3 MB >
              current 1<<19 bound => RAISE bound and update the Go test if n>1024 is adopted.

### If the grid fails (<128-bit at every cell)

Fall back to scenario 1 (honest limitation) and add the negative result to the appendix —
a measured rejection of the cheap lever strengthens the paper's rigor narrative either way.

---

## 8. POST-GRID DECISION (2026-08-26): q/Delta lever VALIDATED — adopt via phased plan

### 8.1 Grid verdict

The alpha hypothesis is CONFIRMED. At q ~= 2^34, security scales with dimension the way normal
LWE does (beta grows with n: 40 -> ~130 -> 264 -> 679). The right-sizing lever converted a
security-dead parameterization into one that CLEARS the target:

| n | best rop | status |
|---|---|---|
| 256 | 2^41.4 | below target |
| 512 | 2^55.3 | below target |
| 1024 | 2^106.2 | close (beta=264) |
| 2048 | **2^222.8** | **>=128-bit CLEARED** (exceeds NIST L5 territory) |

### 8.2 ADOPTION LANDMINES — must be resolved in order, BEFORE constants move

**(L1) q = 2^34-1 is COMPOSITE — the grid value is NOT deployable.**
2^34-1 = (2^17-1)(2^17+1). Hardness estimation is unaffected (lattice attacks ignore
primality), but the SCHEME REQUIRES A PRIME: tally.service.js `modInverseBig` uses Fermat's
little theorem, and Shamir/Lagrange over Z_q needs Z_q to be a FIELD. With composite q,
Lagrange denominators can share factors with q -> non-invertible -> tally fails.
**Resolution:** use the verified prime **q = 2^34 - 41 = 17,179,869,143** (Miller-Rabin verify
again during implementation; do not trust this file's arithmetic alone).
The estimator numbers for 2^34-1 transfer essentially unchanged to 2^34-41.

**(L2) PEDERSEN_Q COUPLING — `ballot_crypto.rs:21-22`: `LWE_Q = PEDERSEN_Q` (Mersenne M61).**
Changing LWE_Q today silently changes the Pedersen/CDS commitment layer's domain too.
**Resolution:** first DECOUPLE the two constants (give LWE its own), then audit every use of
PEDERSEN_Q to confirm the commitment/proof layer is genuinely independent of the LWE modulus
before flipping anything.

**(L3) Range-bound margin.** Delta*N_max < q/2 is EQUALITY at Delta=2^15, N=2^18, q=2^34 — no
margin. With prime q slightly below 2^34, set the documented vote ceiling to
N_max = 250,000 ballots (recompute exact safe value after prime selection).

**(L4) gRPC chunk resize.** Binary v2 cenc at K=4, n=2048 = ~65.6 KB/ballot (~131 KB hex).
Current TALLY_CHUNK=500 would push ~32 MB per RPC > 8 MB gRPC cap. Chunk must drop to <=120
ballots (or switch transport to binary/compression).

**(L5) Redis footprint.** Hex cenc at n=2048 ~ 131 KB/vote => 75k-vote campaign ~ 9.8 GB.
Mitigations to evaluate in the spike: store raw binary Buffers instead of hex (-50%),
base64 (-25%), and re-tune codespace-redis.sh maxmemory.

**(L6) Chaincode pk bound.** Worst-case v3 pk at K=16, n=2048 = 524,562 hex chars > current
1<<19 bound by 274 chars. Raise to 1<<20 + update Go test (or document a K<=15 cap).

**(L7) Node/Rust constant parity.** LWE_Q, LWE_DELTA, boundary-suite expected values,
noise-budget comments, and vote-ceiling docs all move together — single commit, all tests
regenerated, no partial flips.

### 8.3 Phased adoption plan

| Phase | Work | Gate |
|---|---|---|
| A — audit (no behavior change) | Decouple PEDERSEN_Q/LWE_Q; select & re-verify prime q; audit CDS/Pedersen independence from LWE modulus | code review + full test suite green |
| B — perf/memory spike at n=2048 on live stack | envelope µs/ballot (expect ~8x of 15.3 µs), tally accumulate rate, Redis GB per 75k votes (binary vs hex storage), VPS impact at 200 VPS target | proceed only if VPS regression acceptable AND Redis fits ops budget |
| C — adopt | flip constants (q prime, Delta=2^15, n=2048), chunk resize (L4), chaincode bound (L6), regenerate ALL tests incl. boundary suite for new Delta/q, docs + ceiling (L3) | cargo/go/node suites green + fresh benchmark campaign |
| Fallback | if Phase B fails ops budget: adopt n=1024 cell at honest "106-bit concrete" label (still 2.6x today's 41 bits) + keep Module-LWE research ticket open |

### 8.4 Paper-facing claims once Phase C lands

"Ballot ciphertext privacy rests on unstructured LWE with n=2048, q ~= 2^34 (prime),
sigma=3.2, uniform secret; concrete hardness >= 2^222 rop against uSVP/BDD/dual attacks
per the Albrecht lattice-estimator (transcripts archived); vote ceiling 250k ballots per
election; payload 65.6 KB/vote at K=4."

---

## 9. BALLOT-CEILING RESOLUTION (2026-08-26): ceiling is a TUNABLE PARAMETER, not a flaw

**Owner concern:** "262k max ballots makes the system pointless." 
**Resolution:** WRONG READING — the ceiling is q/(2*Delta), i.e. a division of two constants WE
choose. Nothing is deployed. Raise q -> raise the ceiling. Cost: modest security decrease
(estimator-gated). LWE STAYS; the scheme becomes per-election-class parameterized.

### 9.1 New target: 500k-vote campaigns (owner requirement)

Constraint chain (one-hot ballots):
- Noise safety:      Delta >= 12 * sigma * sqrt(N)      -> Delta >= 27,152 -> keep Delta = 65,536 (2^16)
                     (extra margin over the bare minimum: 6-sigma window headroom ~2.4x)
- Range bound:       q >= 2 * Delta * N                  -> q >= 6.55e10 (~2^35.9)
- Field requirement: q PRIME (Shamir/Lagrange/Fermat inverse)

**New parameter proposal:**
    Delta = 65,536 (2^16)
    q     = largest verified prime <= 2^37   (gives N_max ~= 2^37/(2*2^16) = 2^20 = ~1,048,000 ballots)
    n     = 2048 (unchanged)
    sigma = 3.2 (unchanged)

### 9.2 GATE (unchanged discipline): estimator cells REQUIRED before adoption

    Cells: n=2048 AND n=1024 at the selected prime q (~2^37), sigma=3.2, Xs=Uniform(1,q)
    Pass:  n=2048 must clear >=128-bit (predicted ~200+ bits; alpha shift is only ~3 bits of q)
    Fallback ladder if it somehow fails: try smaller Delta (2^15) -> q near 2^36 -> re-run.

### 9.3 What changes downstream when q/Delta move (consolidated checklist)

- [ ] ballot_crypto.rs: LWE_Q (decoupled from PEDERSEN_Q first!), LWE_SCALE, keygen ranges
- [ ] tally.service.js: LWE_Q, LWE_DELTA, lagrange/inverse unchanged (still prime field)
- [ ] Boundary suite: regenerate ALL expected values for new Delta/q
- [ ] Vote ceiling: computed + printed at election creation; stored in TallyCertificate
- [ ] Bit-packing (spool): 37 bits/coefficient (was 35) -> spool ~43KB/ballot packed;
      500k => ~21GB disk — storage plan must account for THIS number, not 17.5GB
- [ ] gRPC chunk: recompute max ballots/chunk under 8MB at new sizes
- [ ] Chaincode pk bound: worst case K=16,n=2048 already exceeds 1<<19 -> raise to 1<<20
- [ ] Docs/cert: ceiling + params recorded per election

### 9.4 Scalability honesty note (for the paper)

Ceiling per election is a DOCUMENTED DESIGN PARAMETER (like Helios-style schemes), tunable at
election creation by choosing q. National-scale deployments count per-constituency
(thousands of parallel tallies, each <= few million ballots), so a ~1M per-election ceiling with
documented derivation is standard practice, not a limitation unique to this design. The true
research frontier (q >= 2^45+) is where alpha degrades enough to threaten 128-bit — that regime
belongs to the Module-LWE follow-up ticket, not to this adoption round.

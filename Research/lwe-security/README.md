# LWE Concrete Bit-Security Estimation Report (Item 1a Gate)

**Date:** 2026-08-26  
**Estimator Tool:** Martin Albrecht's [`lattice-estimator`](https://github.com/malb/lattice-estimator)  
**Execution Environment:** SageMath 10.9 (Python 3.12) inside Docker  
**Target Cryptosystem:** Unstructured LWE over Mersenne Prime $q = 2^{61}-1$, uniform secret $s \in \mathbb{Z}_q^*$, discrete Gaussian noise $\chi_\sigma$.

---

## 1. Concrete Bit-Security Matrix

The lattice estimator was evaluated across the pre-registered 5-cell parameter grid using standard reduction cost models (`BKZ.sieve` / `BKZ.enum`, Core-SVP):

| Cell | Dimension ($n$) | Modulus ($q$) | Noise Std Dev ($\sigma$) | Secret Distribution ($X_s$) | Shortest Vector Attack ($\log_2 \text{rop}$) | Decoded BDD Attack ($\log_2 \text{rop}$) | Dual Lattice Attack ($\log_2 \text{rop}$) | Best Attack Cost ($\log_2 \text{rop}$) |
|---|---|---|---|---|---|---|---|---|
| **A0 (Shipped)** | 256 | $2^{61}-1$ | 3.2 | $\text{Uniform}(1, q)$ | $2^{41.1}$ | $2^{41.1}$ | $2^{42.9}$ | **$\approx 41.1$ bits** |
| **B1 ($n=512$)** | 512 | $2^{61}-1$ | 3.2 | $\text{Uniform}(1, q)$ | $2^{42.4}$ | $2^{42.5}$ | $2^{43.4}$ | **$\approx 42.4$ bits** |
| **B2 ($n=1024$)** | 1024 | $2^{61}-1$ | 3.2 | $\text{Uniform}(1, q)$ | $2^{59.3}$ | $2^{58.7}$ | $2^{60.5}$ | **$\approx 58.7$ bits** |
| **C1 ($\sigma=1000$)** | 256 | $2^{61}-1$ | 1000.0 | $\text{Uniform}(1, q)$ | $2^{41.4}$ | $2^{41.5}$ | $2^{42.9}$ | **$\approx 41.4$ bits** |
| **C2 ($n=512, \sigma=1000$)** | 512 | $2^{61}-1$ | 1000.0 | $\text{Uniform}(1, q)$ | $2^{43.0}$ | $2^{43.2}$ | $2^{44.3}$ | **$\approx 43.0$ bits** |

---

## 2. Cryptographic Analysis & Findings

1. **Root Cause of Low Hardness:**
   - The modulus $q = 2^{61}-1$ is very large relative to the dimension $n=256$, yielding an extremely small noise-to-modulus ratio $\alpha = \sigma / q \approx 2^{-59.3}$.
   - The secret $s \leftarrow \text{Uniform}(1, q)$ is not drawn from a small/ternary distribution ($\{-1, 0, 1\}$).
   - In this parameter regime, lattice basis reduction (Kannan's embedding / uSVP and BDD) requires a very modest BKZ block size ($\beta \approx 40$ for $n=256$, $\beta \approx 94$ for $n=1024$) to recover the secret.

2. **The $\sigma$-Lever Observation:**
   - Increasing $\sigma$ from $3.2 \to 1000$ only increased the hardness by $\approx 0.3$ bits (from $2^{41.1} \to 2^{41.4}$). Because $q \approx 2^{61}$, $\sigma=1000$ still leaves $\alpha \approx 2^{-51}$, which remains within the high-asymptotic-reduction regime for $n=256$.

---

## 3. Pre-Registered Decision Matrix Action

Per `REVIEWER-REMEDIATION-PLAN.md` (§Item 1a Decision Matrix):

> **"Nothing on the grid clears 128-bit:**  
> **Do NOT ship silently under-target.** Present the achieved figures explicitly as a documented limitation in the paper (same honest tradition as §6 limitations), with the raw estimator transcript attached; scope a concrete parameter-research follow-up (e.g. Module/Ring-LWE migration, small/ternary secret-distribution change, or protocol-level noise budgeting redesign) before any 128-bit quantum security claim is made."

---

## 4. Archival Transcripts

All raw output logs from the estimator run are preserved:
- [`A0_shipped.txt`](file:///home/mohmedh/personal/E-Voting-V2/docs/lwe-security/A0_shipped.txt)
- [`B1_n512.txt`](file:///home/mohmedh/personal/E-Voting-V2/docs/lwe-security/B1_n512.txt)
- [`B2_n1024.txt`](file:///home/mohmedh/personal/E-Voting-V2/docs/lwe-security/B2_n1024.txt)
- [`C1_sigma1000.txt`](file:///home/mohmedh/personal/E-Voting-V2/docs/lwe-security/C1_sigma1000.txt)
- [`C2_n512_sigma1000.txt`](file:///home/mohmedh/personal/E-Voting-V2/docs/lwe-security/C2_n512_sigma1000.txt)
- [`grid_estimate.log`](file:///home/mohmedh/personal/E-Voting-V2/docs/lwe-security/grid_estimate.log)

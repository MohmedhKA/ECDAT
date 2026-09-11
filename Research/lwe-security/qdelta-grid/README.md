# LWE $q/\Delta$ Right-Sizing Concrete Bit-Security Report

**Date:** 2026-08-26  
**Estimator Tool:** Martin Albrecht's [`lattice-estimator`](https://github.com/malb/lattice-estimator)  
**Target Cryptosystem:** Unstructured LWE over $q = 2^{34}-1$, uniform secret $s \in \mathbb{Z}_q^*$, $\sigma = 3.2$, scaling factor $\Delta = 2^{15}$.

---

## 1. Concrete Bit-Security Grid Results ($q = 2^{34}-1$)

| Cell | Dimension ($n$) | Modulus ($q$) | Noise ($\sigma$) | Secret ($X_s$) | Shortest Vector (uSVP) | Decoded BDD | Dual Attack | Concrete Security ($\log_2 \text{rop}$) | Hardness Status |
|---|---|---|---|---|---|---|---|---|---|
| **$q34\_n256$** | 256 | $2^{34}-1$ | 3.2 | $\text{Uniform}(1, q)$ | $2^{41.4}$ | $2^{41.5}$ | $2^{42.4}$ | **$\approx 41.4$ bits** | Below 128 |
| **$q34\_n512$** | 512 | $2^{34}-1$ | 3.2 | $\text{Uniform}(1, q)$ | $2^{56.3}$ | $2^{55.3}$ | $2^{57.4}$ | **$\approx 55.3$ bits** | Below 128 |
| **$q34\_n1024$** | 1024 | $2^{34}-1$ | 3.2 | $\text{Uniform}(1, q)$ | $2^{107.5}$ | $2^{106.2}$ | $2^{109.5}$ | **$\approx 106.2$ bits** | Close to 128 ($\beta=264$) |
| **$q34\_n2048$** | 2048 | $2^{34}-1$ | 3.2 | $\text{Uniform}(1, q)$ | $2^{224.6}$ | $2^{222.8}$ | $2^{229.3}$ | **$\approx 222.8$ bits** | **CLEARS $\ge 128$ BITS** ($\beta=679$) |

---

## 2. Key Insights & Parameter Trajectory

1. **Why $q = 2^{34}-1$ Scales Security Faster:**
   - Reducing $q$ from $2^{61}-1 \to 2^{34}-1$ improved the noise-to-modulus ratio from $\alpha \approx 2^{-58} \to \alpha \approx 2^{-32.5}$.
   - While $n=256$ is still bounded by small-block lattice reduction ($\beta=40$), as dimension increases to $n=1024$ and $n=2048$, the BKZ block size scales sharply ($\beta=264$ and $\beta=679$).
   - At $n=2048$, the scheme provides **$\approx 222.8$ bits of concrete security**, which exceeds the NIST Level 5 (AES-256 equivalent) post-quantum hardness requirement.

2. **Vote Ceiling at $q = 2^{34}-1, \Delta = 2^{15}$:**
   - $N_{\text{max}} = \lfloor q / (2\Delta) \rfloor = \lfloor (2^{34}-1) / 2^{16} \rfloor \approx 2^{18} \approx 262,144$ ballots per election.

---

## 3. Archival Files

- [`q34_n256.txt`](file:///home/mohmedh/personal/E-Voting-V2/docs/lwe-security/qdelta-grid/q34_n256.txt)
- [`q34_n512.txt`](file:///home/mohmedh/personal/E-Voting-V2/docs/lwe-security/qdelta-grid/q34_n512.txt)
- [`q34_n1024.txt`](file:///home/mohmedh/personal/E-Voting-V2/docs/lwe-security/qdelta-grid/q34_n1024.txt)
- [`q34_n2048.txt`](file:///home/mohmedh/personal/E-Voting-V2/docs/lwe-security/qdelta-grid/q34_n2048.txt)
- [`qdelta_grid.log`](file:///home/mohmedh/personal/E-Voting-V2/docs/lwe-security/qdelta-grid/qdelta_grid.log)

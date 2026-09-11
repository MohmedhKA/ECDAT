import sys
sys.path.insert(0, '/work/lattice-estimator')
sys.path.insert(0, '/tmp/lattice-estimator')
from estimator import *

q = 137438953447 # 2^37 - 25 (verified prime)
sigma = 3.2

cells = [
    ("q37_n1024", 1024, q, sigma),
    ("q37_n2048", 2048, q, sigma),
]

print(f"Lattice-Estimator Grid for Prime q = {q} (2^37 - 25), sigma = {sigma}\n", flush=True)

for name, n, q_val, sig in cells:
    print(f"\n=======================================================", flush=True)
    print(f"Running Cell: {name} (n={n}, q={q_val}, sigma={sig})", flush=True)
    print(f"=======================================================", flush=True)
    
    p = LWE.Parameters(n=n, q=q_val, Xs=ND.Uniform(1, q_val), Xe=ND.DiscreteGaussian(sig))
    res = LWE.estimate(p)
    print(res, flush=True)
    
    try:
        with open(f"/work/out/q37-grid/{name}.txt", "w") as f:
            f.write(f"Parameters: n={n}, q={q_val}, sigma={sig}, Xs=Uniform(1, q)\n\n")
            f.write(str(res) + "\n")
    except Exception as e:
        print(f"Warning: Failed to write {name}.txt: {e}", flush=True)

print("\n--- ALL Q37 CELLS COMPLETE ---", flush=True)

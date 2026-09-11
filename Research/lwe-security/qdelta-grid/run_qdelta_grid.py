import sys
sys.path.insert(0, '/work/lattice-estimator')
sys.path.insert(0, '/tmp/lattice-estimator')
from estimator import *

cells = [
    ("q34_n256", 256, 2**34 - 1, 3.2),
    ("q34_n512", 512, 2**34 - 1, 3.2),
    ("q34_n1024", 1024, 2**34 - 1, 3.2),
    ("q34_n2048", 2048, 2**34 - 1, 3.2),
]

for name, n, q, sigma in cells:
    print(f"\n=======================================================", flush=True)
    print(f"Running Cell: {name} (n={n}, q=2^34-1, sigma={sigma})", flush=True)
    print(f"=======================================================", flush=True)
    
    p = LWE.Parameters(n=n, q=q, Xs=ND.Uniform(1, q), Xe=ND.DiscreteGaussian(sigma))
    res = LWE.estimate(p)
    print(res, flush=True)
    
    try:
        with open(f"/work/out/qdelta-grid/{name}.txt", "w") as f:
            f.write(f"Parameters: n={n}, q={q}, sigma={sigma}, Xs=Uniform(1, q)\n\n")
            f.write(str(res) + "\n")
    except Exception as e:
        print(f"Warning: Failed to write {name}.txt: {e}", flush=True)

print("\n--- ALL Q-DELTA CELLS COMPLETE ---", flush=True)

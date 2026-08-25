# Official estimator workflow

The old `run_lattice_estimator.py` file is a local Core-SVP model. Its output
must not be presented as an independent security estimate.

Use Martin Albrecht's `lattice-estimator` at this exact revision:

```text
27a581bb8e9d49f5e9e2db315bd48ac769d5f5f5
```

The project requires SageMath. From a Sage shell with the pinned estimator on
`PYTHONPATH`, run:

```bash
sage scripts/run_official_estimator.sage | tee official_estimator_output.txt
```

The script deliberately labels its output as diagnostic. The current paper
does not yet provide the reduction needed to identify a formal MLWE instance,
and the exact self-target MSIS extraction dimensions and norm bound are not
fixed. Once the core proof is complete, replace the diagnostic tuples with the
instance stated by the theorem and record all of the following in the paper:

- estimator repository and full commit hash;
- SageMath version;
- exact dimensions, modulus, distributions, sample count, and norm;
- every enabled attack and cost model;
- classical and quantum interpretation, without assigning a NIST category by
  analogy to ML-DSA.

"""Diagnostic SIS estimates for the current PABS-CRF parameter file.

Run this script with SageMath and lattice-estimator commit
27a581bb8e9d49f5e9e2db315bd48ac769d5f5f5.  The instances below are not a
substitute for a reduction: they flatten the implemented module matrix and
show how strongly the result depends on the extraction bound.
"""

from estimator import SIS
from sage.all import oo


TIERS = (
    {
        "name": "current-tier-k4",
        "ring_degree": 256,
        "q": 8380417,
        "k": 4,
        "m": 19,
        "gamma1": 4190207,
        "configured_beta": 78,
        "sampled_witness_beta": 700596,
    },
    {
        "name": "current-tier-k6",
        "ring_degree": 256,
        "q": 8380417,
        "k": 6,
        "m": 35,
        "gamma1": 4190207,
        "configured_beta": 98,
        "sampled_witness_beta": 1139250,
    },
    {
        "name": "current-tier-k8",
        "ring_degree": 256,
        "q": 8380417,
        "k": 8,
        "m": 55,
        "gamma1": 4190207,
        "configured_beta": 120,
        "sampled_witness_beta": 1458060,
    },
)


def estimate_instance(tier, label, length_bound):
    params = SIS.Parameters(
        n=tier["k"] * tier["ring_degree"],
        q=tier["q"],
        m=tier["m"] * tier["ring_degree"],
        length_bound=length_bound,
        norm=oo,
        tag=f'{tier["name"]}-{label}',
    )
    print(f"\n[{params.tag}]")
    print(params)
    print(SIS.estimate(params))


print("lattice-estimator diagnostic for the current implementation")
print("This is not a formal PABS-CRF security estimate.")
for tier in TIERS:
    # A two-transcript extraction can be as large as twice the accepted
    # response bound.  The exact reduction may produce a different instance.
    configured_response_bound = 2 * (tier["gamma1"] - tier["configured_beta"])
    witness_aware_response_bound = 2 * (
        tier["gamma1"] - tier["sampled_witness_beta"]
    )
    estimate_instance(tier, "configured-response", configured_response_bound)
    estimate_instance(tier, "witness-aware-response", witness_aware_response_bound)

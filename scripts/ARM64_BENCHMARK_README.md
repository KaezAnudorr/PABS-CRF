# Native ARM64 benchmark

The workflow in `.github/workflows/native-arm64-benchmark.yml` runs the PABS-CRF
prototype and the three ML-DSA primitive references on one native
`ubuntu-24.04-arm` GitHub-hosted runner. It is manually triggered so that paper
measurements are not mixed with ordinary CI runs.

## Procedure

1. Push the repository, including `Cargo.lock`, to GitHub.
2. Open **Actions > Native ARM64 benchmark > Run workflow**.
3. Keep the iteration count fixed across all reported runs.
4. Download the `pabs-crf-native-arm64-*` artifact after the job succeeds.
5. Retain the runner manifest, six timing JSON files, and six `/usr/bin/time -v`
   logs together as the raw evidence for one run.

The six configurations execute in separate processes on the same runner. Peak
RSS is therefore recorded per configuration instead of once for the combined
benchmark. The ML-DSA rows are same-platform primitive references; they are not
equivalent-functionality ABS baselines.

Do not cite an ARM result merely because the workflow exists. Report values only
from a completed artifact, name the hosted runner and image, disclose that the
host is virtualized, and repeat the full workflow enough times to characterize
run-to-run variation.

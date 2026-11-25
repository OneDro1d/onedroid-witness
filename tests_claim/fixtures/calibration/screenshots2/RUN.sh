#!/bin/sh
# Run inside the calibration pod (pod.yaml / pod-gate.yaml) once /cal/in/READY exists: /cal/in holds the set (cases.json, images/,
# pages/, regression/, measure.py, measure_gate.py), and for the readability gate also the package to test as /cal/in/pkg.
# Usage: sh RUN.sh <script> ; prints to stdout (the pod log), writes /cal/out.
script="${1:-measure_gate.py}"
cd /cal/in || exit 1
PYTHONPATH="${CAL_PKG:-/app}" PYTHONDONTWRITEBYTECODE=1 python3 "/cal/in/$script" /cal/in /cal/out

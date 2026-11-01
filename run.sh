#!/usr/bin/env bash
echo "========================================================"
echo "  Starting CodeSanctum AI - DevSecOps Engine"
echo "  Team: Valerion Coders | HACKVERSE 2026"
echo "========================================================"
pip install -r requirements.txt
python -m pytest test_codesanctum.py -v
python app.py

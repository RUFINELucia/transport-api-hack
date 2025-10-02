#!/usr/bin/env python3
"""
api_audit.py

Script d'audit basique d'une API REST (usage éducatif / audit autorisé uniquement).

Usage examples:
    python api_audit.py --api mock_api.json --output results/report.json --dry-run
    python api_audit.py --api mock_api.json --base-url https://api.example.com --methods GET,POST --output results/report.json
"""

import argparse
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Tuple

try:
    import requests
except Exception:
    print("Erreur: 'requests' non installé. Installe avec `pip install requests`.")
    raise

SENSITIVE_KEYWORDS = [
    "password", "passwd", "pwd", "secret", "api_key", "apikey", "token", "ssn", "socialsecurity",
    "creditcard", "card_number"
]

ADMIN_PATH_INDICATORS = ["admin", "manage", "debug", "config", "internal", "backoffice"]


def load_api_spec(path: Path) -> Dict:
    if not path.exists():
        raise FileNotFoundError(f"Spécification API non trouvée: {path}")
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def build_targets(spec: Dict, methods_filter: List[str]) -> List[Tuple[str, str]]:
    """
    Attendu spec minimal (exemple):
    {
        "endpoints": [
            { "path": "/v1/status", "methods": ["GET"] },
            { "path": "/admin/users", "methods": ["GET","POST"] }
        ]
    }
    Retourne une liste (path, method) pour test.
    """
    targets = []
    for ep in spec.get("endpoints", []):
        path = ep.get("path")
        methods = ep.get("methods", ["GET"])
        for m in methods:
            m_up = m.upper()
            if methods_filter and m_up not in methods_filter:
                continue
            targets.append((path, m_up))
    return targets


def looks_like_admin(path: str) -> bool:
    lower = path.lower()
    return any(ind in lower for ind in ADMIN_PATH_INDICATORS)


def inspect_response_text(text: str) -> List[str]:
    findings = []
    low = text.lower()
    for kw in SENSITIVE_KEYWORDS:
        if kw in low:
            findings.append(kw)
    return findings


def test_target(session: requests.Session, base_url: str, path: str, method: str, timeout: int, dry_run: bool):
    """
    Execute le test pour un (path, method). Retourne un dict avec les résultats.
    """
    full_url = base_url.rstrip("/") + "/" + path.lstrip("/")
    result = {
        "path": path,
        "method": method,
        "url": full_url,
        "status_code": None,
        "reason": None,
        "needs_auth": None,
        "sensitive_in_response": [],
        "notes": []
    }

    # Heuristique: si le chemin contient "admin" etc. et qu'on peut accéder => suspicious
    if dry_run:
        # Simulation prudente : ne renvoie 200 que si path contient 'status' ou 'public'
        if re.search(r"(status|health|public)", path, re.IGNORECASE):
            result["status_code"] = 200
            result["reason"] = "SIMULATED OK"
            result["needs_auth"] = False
        elif looks_like_admin(path):
            result["status_code"] = 403
            result["reason"] = "SIMULATED FORBIDDEN"
            result["needs_auth"] = True
        else:
            result["status_code"] = 404
            result["reason"] = "SIMULATED NOT FOUND"
            result["needs_auth"] = True
        # simulated content
        simulated_body = ""
        if result["status_code"] == 200:
            simulated_body = '{"status":"ok"}'
        else:
            simulated_body = ''
        result["sensitive_in_response"] = inspect_response_text(si


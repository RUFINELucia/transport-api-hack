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
        result["sensitive_in_response"] = inspect_response_text(simulated_body)
        return result

    # réel
    try:
        # On limite les méthodes potentiellement dangereuses à la logique de requests
        kwargs = {"timeout": timeout}
        resp = None
        if method == "GET":
            resp = session.get(full_url, **kwargs)
        elif method == "POST":
            # POST sans payload minimal
            resp = session.post(full_url, data={}, **kwargs)
        elif method == "PUT":
            resp = session.put(full_url, data={}, **kwargs)
        elif method == "DELETE":
            resp = session.delete(full_url, **kwargs)
        else:
            # méthodes moins communes : essayer request generique
            resp = session.request(method, full_url, **kwargs)

        result["status_code"] = resp.status_code
        result["reason"] = resp.reason

        # Heuristique: si 200 pour path admin-like, alerte "no auth required"
        if looks_like_admin(path) and resp.status_code == 200:
            result["needs_auth"] = False
            result["notes"].append("Admin-like endpoint returned 200: possible missing auth.")
        else:
            # si 401/403 -> probablement nécessite auth
            if resp.status_code in (401, 403):
                result["needs_auth"] = True
            else:
                result["needs_auth"] = False

        # Cherche mots-clés sensibles dans le corps (textuel)
        content_type = resp.headers.get("Content-Type", "") if resp is not None else ""
        body_text = ""
        try:
            if "application/json" in content_type.lower():
                body_text = json.dumps(resp.json())
            else:
                # limiter la taille lue pour éviter trop de données
                body_text = resp.text[:10000]
        except Exception:
            body_text = (resp.text[:10000] if resp is not None else "")

        result["sensitive_in_response"] = inspect_response_text(body_text)
        if result["sensitive_in_response"]:
            result["notes"].append(f"Response contains possible sensitive keywords: {result['sensitive_in_response']}")

    except requests.exceptions.RequestException as e:
        result["reason"] = f"ERROR: {e}"
        result["notes"].append("RequestException occurred (timeout, conn error, etc.).")

    return result


def run_checks(base_url: str, targets: List[Tuple[str, str]], timeout: int, concurrency: int, dry_run: bool):
    results = []
    session = requests.Session()
    # headers minimal
    session.headers.update({"User-Agent": "transport-api-hack/0.1 (+audit-tool)"})

    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = {}
        for path, method in targets:
            fut = ex.submit(test_target, session, base_url, path, method, timeout, dry_run)
            futures[fut] = (path, method)
        for fut in as_completed(futures):
            try:
                res = fut.result()
            except Exception as e:
                res = {
                    "path": futures[fut][0],
                    "method": futures[fut][1],
                    "status_code": None,
                    "reason": f"EXCEPTION: {e}",
                    "needs_auth": None,
                    "sensitive_in_response": [],
                    "notes": ["Unhandled exception in worker."]
                }
            results.append(res)
    return results


def summarize_findings(results: List[Dict]) -> Dict:
    summary = {
        "total_tested": len(results),
        "potential_issues": 0,
        "issues": []
    }
    for r in results:
        issue = False
        notes = list(r.get("notes", []))
        # heuristiques d'alerte
        if looks_like_admin(r["path"]) and r.get("status_code") == 200 and r.get("needs_auth") is False:
            issue = True
            notes.append("Admin endpoint accessible without authentication.")
        if r.get("method") in ("POST", "PUT", "DELETE") and r.get("status_code") in (200, 201, 204) and r.get("needs_auth") is False:
            issue = True
            notes.append("Unsafe method allowed without authentication.")
        if r.get("sensitive_in_response"):
            issue = True
            notes.append(f"Sensitive keywords in response: {r.get('sensitive_in_response')}")
        if issue:
            summary["potential_issues"] += 1
            summary["issues"].append({
                "path": r["path"],
                "method": r["method"],
                "status_code": r.get("status_code"),
                "notes": notes
            })
    return summary


def save_report(report: Dict, output_path: Path):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"[OK] Rapport enregistré : {output_path}")


def parse_methods_arg(s: str) -> List[str]:
    if not s:
        return []
    return [p.strip().upper() for p in s.split(",") if p.strip()]


def main():
    parser = argparse.ArgumentParser(description="Audit basique d'une API REST à partir d'une spec JSON (usage éducatif).")
    parser.add_argument("--api", required=True, help="Fichier JSON décrivant l'API (ex: mock_api.json)")
    parser.add_argument("--base-url", default="", help="URL de base à préfixer aux chemins (ex: https://api.example.com). Si vide, seuls les chemins relatifs sont pris (utilisé surtout en dry-run).")
    parser.add_argument("--methods", help="Méthodes HTTP à tester, séparées par des virgules (ex: GET,POST). Par défaut: GET,POST,PUT,DELETE")
    parser.add_argument("--timeout", type=int, default=5, help="Timeout requêtes en secondes (défaut: 5s)")
    parser.add_argument("--concurrency", type=int, default=8, help="Nombre max de threads (défaut: 8)")
    parser.add_argument("--output", "-o", default="results/report.json", help="Fichier de sortie JSON du rapport")
    parser.add_argument("--dry-run", action="store_true", help="Mode simulation (aucun appel réseau si activé)")
    args = parser.parse_args()

    # Avertissement
    if not args.dry_run:
        print("ATTENTION: Vous lancez des requêtes réseau réelles. Assurez-vous d'avoir l'autorisation explicite pour auditer la cible.")
        confirm = input("Continuer ? (oui/non) : ").strip().lower()
        if confirm not in ("oui", "o", "yes", "y"):
            print("Abandon.")
            sys.exit(1)

    api_spec = load_api_spec(Path(args.api))
    default_methods = ["GET", "POST", "PUT", "DELETE"]
    methods_filter = parse_methods_arg(args.methods) or default_methods
    targets = build_targets(api_spec, methods_filter)

    if not targets:
        print("Aucun endpoint à tester trouvé dans la spec fournie.")
        sys.exit(2)

    # base_url fallback (si vide et dry_run True, on utilisera 'http://example.invalid' pour formater l'URL)
    base_url = args.base_url if args.base_url else ("http://example.invalid" if args.dry_run else "")
    if not base_url and not args.dry_run:
        print("Erreur: --base-url requis si --dry-run n'est pas utilisé (pour éviter des requêtes incohérentes).")
        sys.exit(2)

    print(f"Lancement des tests sur {len(targets)} cibles (dry-run={args.dry_run})...")
    results = run_checks(base_url, targets, args.timeout, args.concurrency, args.dry_run)

    summary = summarize_findings(results)
    report = {
        "meta": {
            "api_file": args.api,
            "base_url": base_url,
            "dry_run": args.dry_run,
            "methods_tested": methods_filter
        },
        "results": results,
        "summary": summary
    }

    save_report(report, Path(args.output))
    print("Résumé:")
    print(f"  Total testés: {summary['total_tested']}")
    print(f"  Problèmes potentiels: {summary['potential_issues']}")
    if summary["potential_issues"] > 0:
        print("  Détails sommaires des problèmes détectés:")
        for i, issue in enumerate(summary["issues"], 1):
            print(f"   {i}. {issue['path']} [{issue['method']}] -> {issue.get('notes')}")


if __name__ == "__main__":
    main()

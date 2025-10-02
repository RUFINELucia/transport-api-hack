# transport-api-hack
Script d’audit basique d’une API REST publique utilisée par une société de transport (fictive). Cherche des endpoints non sécurisés.

<p align="center">
  <img src="lucia-rufine-logo.jpg" alt="lucia-rufine" width="400"/>
</p>

## Objectif

- Découvrir les endpoints exposés (GET/POST/PUT/DELETE) à partir d'une description JSON (ex : `mock_api.json`).
- Vérifier des points basiques de sécurité : absence d'authentification, méthodes unsafe disponibles, code d'état inattendu (200 sur endpoints d'administration), réponses contenant des informations sensibles évidentes.
- Générer un rapport sommaire (format texte/JSON) listant les problèmes trouvés.

## Contenu du dépôt

- `README.md` — ceci.
- `api_audit.py` — script d'audit principal (Python).
- `mock_api.json` — description factice de l'API (pour tests et démonstration).
- `results/` — dossier de sortie (généré par le script) contenant les rapports.

## Installation

1. Cloner le dépôt :

```bash
git clone https://github.com/TON_COMPTE/transport-api-hack.git
cd transport-api-hack
```

2. (Optionnel) Créer un environnement virtuel et installer les dépendances :

3. ```bash
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
.\\.venv\\Scripts\\activate # Windows
pip install -r requirements.txt
```

requirements.txt contient par défaut requests (utilisé pour les appels HTTP) et éventuellement tqdm pour la barre de progression.

## Usage

Audit d'une API basée sur mock_api.json :

```bash
python api_audit.py --api mock_api.json --output results/report.json
```

Audit en mode « dry-run » (n'effectue pas d'appels réseau réels — utile si mock_api.json contient uniquement des chemins) :

```bash
python api_audit.py --api mock_api.json --dry-run
```

Options utiles :

- --base-url — préfixe à ajouter aux chemins (ex : https://api.transport.example).

- --methods — liste de méthodes HTTP à tester (par défaut : GET, POST, PUT, DELETE).

- --timeout — timeout pour les requêtes HTTP en secondes.

- --concurrency — degré de parallélisme (optionnel).

## Exemple de rapport

Le script produit un rapport JSON/texte listant :

- endpoint
- méthode
- statut HTTP obtenu
- indicateur needs_auth si l'endpoint semble accessible sans auth
- notes textuelles sur tout comportement suspect

## Avertissements & limites

- Outil basique : ne remplace pas un scanner professionnel ou un pentest complet.
- Doit être utilisé uniquement sur des cibles de test ou avec autorisation.

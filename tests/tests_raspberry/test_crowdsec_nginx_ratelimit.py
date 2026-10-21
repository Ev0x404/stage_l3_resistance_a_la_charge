import threading
import time
import requests
import socket
from src.Python.network_utilities import run_slowloris_attack_thread
from src.Python.server_metrics_raspberry import ServerMetrics

RASPBERRY_IP = "192.168.1.40"
RASPBERRY_USER = "raspberry"
RASPBERRY_PASS = "1234"
TARGET_URL = f"http://{RASPBERRY_IP}/index.php"
TARGET_PORT = 80
TIMEOUT = 5
TOTAL_REQUESTS = 150
BANTIME = 30


def get_local_ipv4():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


def is_http_reachable(url=TARGET_URL, timeout=TIMEOUT):
    try:
        r = requests.get(url, timeout=timeout)
        print(f"[DEBUG] Status: {r.status_code}, Body: {repr(r.text)}")
        return r.status_code == 200 and "OK" in r.text.strip()
    except Exception as e:
        print(f"[DEBUG] Exception dans is_http_reachable: {e}")
        return False


# Cette fonction vérifie que CrowdSec bannit l'IP après un flood HTTP massif, puis restaure l'accès après expiration du bannissement
def test_crowdsec_ratelimit_detection():
    print("\n--- DÉBUT DU TEST CROWDSEC HTTP RATE LIMIT ---")

    metrics = ServerMetrics(host=RASPBERRY_IP, user=RASPBERRY_USER, password=RASPBERRY_PASS)
    my_ip = get_local_ipv4()
    print(f"[i] IP locale détectée: {my_ip}")

    metrics.disable_fail2ban()

    print(f"[*] Activation de CrowdSec avec un ban de {BANTIME}s...")
    metrics.enable_crowdsec_http_ratelimit(BANTIME)

    print("[*] Vérification de l’accessibilité du serveur...")
    assert is_http_reachable(), "index.php inaccessible avant le test"

    def send_request(i):
        try:
            r = requests.get(TARGET_URL, timeout=TIMEOUT, headers={"Connection": "close"})
            print(f"[Thread {i+1}] {r.status_code}")
        except Exception as e:
            print(f"[Thread {i+1}] EXCEPTION: {e}")

    print(f"[>] Envoi de {TOTAL_REQUESTS} requêtes simultanées via threads...")
    threads = []
    for i in range(TOTAL_REQUESTS):
        t = threading.Thread(target=send_request, args=(i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print("[*] Attente de 5 secondes pour laisser CrowdSec analyser les logs...")
    time.sleep(5)

    print(f"[~] Attente de {BANTIME + 5} sec pour expiration du ban...")
    time.sleep(BANTIME + 5)
    
    print("[*] Vérification de l’état de bannissement CrowdSec...")
    banned = metrics.was_ip_banned_by_crowdsec(my_ip)
    assert banned, f"IP {my_ip} non bannie par CrowdSec malgré l’abus"
    print(f"[✔] IP {my_ip} correctement bannie par CrowdSec")

    assert is_http_reachable(), "Le service n'est pas restauré après expiration du bannissement"
    print(f"[+] IP {my_ip} confirmée comme bannie puis débannie correctement")

    print("[*] Réinitialisation de CrowdSec après test...")
    metrics.disable_crowdsec()
    metrics.restore_default_firewall_rules()

    print("--- FIN DU TEST CROWDSEC ---\n")
    

# Cette fonction teste la détection Slowloris par CrowdSec et la restauration du service après bannissement
def test_crowdsec_slowloris_detection():
    print("\n--- DÉBUT DU TEST CROWDSEC + SLOWLORIS ---")

    metrics = ServerMetrics(host=RASPBERRY_IP, user=RASPBERRY_USER, password=RASPBERRY_PASS)
    my_ip = get_local_ipv4()
    print(f"[i] IP locale détectée: {my_ip}")

    metrics.disable_fail2ban()

    print("[*] Activation de CrowdSec avec un ban de 30s...")
    metrics.enable_crowdsec_http_ratelimit(30)

    print("[*] Vérification que le service est disponible avant attaque...")
    assert is_http_reachable(), "index.php inaccessible avant le test"

    print("[*] Lancement de l'attaque Slowloris (15 threads)...")
    attacker = run_slowloris_attack_thread(RASPBERRY_IP, TARGET_PORT, 200, 30)

    print("[*] Attente de 30 secondes pour effet + analyse CrowdSec...")
    time.sleep(30)

    print("[*] Arrêt de l'attaque Slowloris...")
    attacker.join()

    print("[*] Vérification si CrowdSec a banni l’IP...")
    assert metrics.was_ip_banned_by_crowdsec(my_ip), f"L'IP {my_ip} n'a pas été bannie par CrowdSec"
    print(f"[✔] IP {my_ip} correctement bannie par CrowdSec")

    print("[*] Attente de 5 secondes pour laisser CrowdSec analyser les logs...")
    time.sleep(5)

    print(f"[~] Attente de {BANTIME + 5} sec pour expiration du ban...")
    time.sleep(BANTIME + 5)

    assert is_http_reachable(), "Service non restauré après le bannissement"
    print(f"[+] Service restauré pour l'IP {my_ip}")

    print("[*] Nettoyage...")
    metrics.disable_crowdsec()
    metrics.restore_default_firewall_rules()

    print("--- FIN DU TEST CROWDSEC + SLOWLORIS ---\n")


# Cette fonction combine NGINX rate-limit et CrowdSec, et valide blocage+restauration.
def test_crowdsec_and_nginx_ratelimit_detection():
    print("\n--- DÉBUT DU TEST NGINX RATE LIMIT + CROWDSEC ---")

    metrics = ServerMetrics(host=RASPBERRY_IP, user=RASPBERRY_USER, password=RASPBERRY_PASS)
    my_ip = get_local_ipv4()
    print(f"[i] IP locale détectée: {my_ip}")

    print("[*] Désactivation temporaire de Fail2Ban...")
    metrics.disable_fail2ban()
    
    print("[*] Désactivation de recent/ipset...")
    metrics.disable_iptables_recent_ratelimit()

    print("[*] Activation du rate limit NGINX...")
    metrics.enable_nginx_ratelimit()

    print(f"[*] Activation de CrowdSec avec un ban de {BANTIME}s...")
    metrics.enable_crowdsec_http_ratelimit(BANTIME)

    print("[*] Vérification de l’accessibilité du serveur...")
    assert is_http_reachable(), "index.php inaccessible avant le test"

    success_count = 0
    blocked_count = 0
    lock = threading.Lock()

    def send_request(i):
        nonlocal success_count, blocked_count
        try:
            r = requests.get(TARGET_URL, timeout=TIMEOUT, headers={"Connection": "close"})
            with lock:
                if r.status_code == 200:
                    success_count += 1
                elif r.status_code == 503:
                    blocked_count += 1
            print(f"[Thread {i+1}] {r.status_code}")
        except Exception as e:
            print(f"[Thread {i+1}] EXCEPTION: {e}")
            with lock:
                blocked_count += 1

    print(f"[>] Envoi de {TOTAL_REQUESTS} requêtes simultanées via threads...")
    threads = []
    for i in range(TOTAL_REQUESTS):
        t = threading.Thread(target=send_request, args=(i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print(f"[*] Résultat : {success_count} OK | {blocked_count} bloquées ou échouées")
    assert blocked_count > 0, "Le rate limit ne semble pas avoir été déclenché"

    print("[*] Attente de 5 secondes pour laisser CrowdSec analyser les logs...")
    time.sleep(5)

    print(f"[~] Attente de {BANTIME} sec pour expiration du ban...")
    time.sleep(BANTIME)

    print("[*] Vérification de l’état de bannissement CrowdSec...")
    banned = metrics.was_ip_banned_by_crowdsec(my_ip)
    assert banned, f"IP {my_ip} non bannie par CrowdSec malgré l’abus"
    print(f"[✔] IP {my_ip} correctement bannie par CrowdSec")

    assert is_http_reachable(), "Le service n'est pas restauré après expiration du bannissement"
    print(f"[+] IP {my_ip} confirmée comme bannie puis débannie correctement")

    print("[*] Réinitialisation de CrowdSec après test...")
    metrics.disable_crowdsec()

    print("[*] Restauration de la configuration NGINX sans ratelimit...")
    metrics.disable_nginx_ratelimit()
    metrics.restore_default_firewall_rules()

    print("--- FIN DU TEST NGINX RATE LIMIT + CROWDSEC ---\n")


# Cette fonction teste l'ipset et le module recent d'iptables + NGINX rate-limit, et vérifie le bannissement puis le rétablissement
def test_nginx_ratelimit_recent_ipset_detection():
    print("\n--- DÉBUT DU TEST NGINX RATE LIMIT + CROWDSEC ---")
    
    metrics = ServerMetrics(host=RASPBERRY_IP, user=RASPBERRY_USER, password=RASPBERRY_PASS)
    my_ip = get_local_ipv4()
    print(f"[i] IP locale détectée: {my_ip}")


    # Désactiver Fail2Ban, activer NGINX ratelimit + CrowdSec
    metrics.disable_fail2ban()
    metrics.enable_nginx_ratelimit()
    metrics.disable_crowdsec()
    metrics.enable_iptables_recent_ratelimit(threshold=100, seconds=1, bantime=40)

    assert is_http_reachable(), "index.php inaccessible avant le test"

    success_count = blocked_count = 0
    lock = threading.Lock()

    def send_request(i):
        nonlocal success_count, blocked_count
        try:
            r = requests.get(TARGET_URL, timeout=TIMEOUT, headers={"Connection": "close"})
            with lock:
                if r.status_code == 200:
                    success_count += 1
                else:
                    blocked_count += 1
            print(f"[Thread {i+1}] {r.status_code}")
        except Exception:
            with lock:
                blocked_count += 1

    print(f"[>] Envoi de {TOTAL_REQUESTS} requêtes simultanées via threads...")
    threads = [threading.Thread(target=send_request, args=(i,)) for i in range(TOTAL_REQUESTS)]
    for t in threads: t.start()
    for t in threads: t.join()

    time.sleep(0.5)  # laisser iptables/ipset appliquer
    print(f"[*] Résultat flood : {success_count} OK | {blocked_count} bloquées/échouées")
    assert metrics.is_ip_in_ipset(my_ip), "L’IP n’a pas été ajoutée à l’ipset"

    print("[*] Attente du retour du service après expiration du ban...")
    metrics.wait_until_http_restored(TARGET_URL, timeout_seconds=120)
    print(f"[+] IP {my_ip} débannie correctement")

    assert is_http_reachable(), "Service non restauré après expiration du ban"
    print(f"[+] IP {my_ip} débannie correctement")

    # Cleanup
    metrics.disable_nginx_ratelimit()
    metrics.force_disable_recent_ipset()
    metrics.restore_default_firewall_rules()
    print("--- FIN DU TEST ---\n")

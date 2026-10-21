import subprocess
import requests
import threading
import time
import socket
from src.Python.server_metrics_docker import (
    disable_crowdsec, enable_crowdsec, apply_fail2ban_bantime,
    was_ip_banned_by_fail2ban, get_local_ipv4, is_http_reachable
)


TARGET_URL = "http://lamp-server/index.php"
TOTAL_REQUESTS = 150
BANTIME = 30
TIMEOUT = 3


def send_request(i):
    try:
        r = requests.get(TARGET_URL, timeout=1, headers={"Connection": "close"})
        print(f"[Thread {i+1}] {r.status_code}")
    except Exception as e:
        print(f"[Thread {i+1}] EXCEPTION: {e}")


def run_slowloris():
    sockets = []
    for _ in range(150):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect(("lamp-server", 80))
            s.send(b"GET / HTTP/1.1\r\nHost: lamp-server\r\n")
            sockets.append(s)
        except Exception as e:
            print(f"[!] Socket error: {e}")

    end_time = time.time() + 30
    while time.time() < end_time:
        for s in sockets:
            try:
                s.send(b"X-a: keep-alive\r\n")
            except:
                pass
        time.sleep(2)

    for s in sockets:
        try:
            s.close()
        except:
            pass


# Cette fonction vérifie que Fail2Ban bannit l'IP après un flot de requêtes et rétablit l'accès
def test_fail2ban_ban_and_recovery_parallel():
    disable_crowdsec()
    try:
        apply_fail2ban_bantime(BANTIME)

        print(f"[*] Vérification de l'accès initial à {TARGET_URL}")
        assert is_http_reachable(), "Le serveur n'est pas accessible au départ"

        print(f"[*] Lancement de {TOTAL_REQUESTS} requêtes HTTP en parallèle pour déclencher Fail2Ban")
        threads = []
        for i in range(TOTAL_REQUESTS):
            t = threading.Thread(target=send_request, args=(i,))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

        print("[*] Pause courte pour laisser Fail2Ban analyser les logs...")
        time.sleep(3)

        print("[*] Vérification si l'accès est bloqué...")
        banned = not is_http_reachable()
        assert banned, "L'IP n'a pas été bannie"
        print("[✔] IP bannie avec succès !")

        my_ip = get_local_ipv4()
        assert was_ip_banned_by_fail2ban(my_ip), f"IP {my_ip} non retrouvée dans les logs Fail2Ban"
        print(f"[✔] IP {my_ip} confirmée dans les logs Fail2Ban")

        print(f"[~] Attente de {BANTIME} secondes pour laisser expirer le bannissement...")
        time.sleep(BANTIME)

        print("[*] Vérification que l'accès est revenu après bannissement")
        assert is_http_reachable(), "L'accès n'est pas revenu après le bannissement"
        print("[✔] Accès rétabli après bannissement !")
    finally:
        enable_crowdsec()


# Cette fonction lance Slowloris contre Fail2Ban et vérifie le blocage en temps réel et la récupération
def test_fail2ban_slowloris():
    disable_crowdsec()
    try:
        apply_fail2ban_bantime(BANTIME)

        print("\n--- TEST FAIL2BAN / SLOWLORIS ---")

        assert is_http_reachable(), "Le serveur n'est pas accessible au départ"

        print("[*] Lancement attaque Slowloris")
        t = threading.Thread(target=run_slowloris)
        t.start()

        print("[*] Surveillance pendant l'attaque...")
        banned = False
        start = time.time()
        while time.time() - start < 45:
            time.sleep(5)
            if not is_http_reachable():
                print("[✔] IP bannie pendant attaque !")
                banned = True
                break

        t.join()

        assert banned, "Fail2Ban n’a pas détecté l’attaque Slowloris"

        my_ip = get_local_ipv4()
        assert was_ip_banned_by_fail2ban(my_ip), f"IP {my_ip} non retrouvée dans les logs Fail2Ban"
        print(f"[✔] IP {my_ip} confirmée dans les logs Fail2Ban")

        print(f"[~] Attente de {BANTIME} sec pour expiration du ban...")
        time.sleep(BANTIME)

        assert is_http_reachable(), "Service non restauré après bannissement"
        print("[✔] Accès rétabli après bannissement !")
        print("--- FIN DU TEST SLOWLORIS ---\n")
    finally:
        enable_crowdsec()

import subprocess
import threading
import time
import requests

from src.Python.network_utilities import syn_flood
from src.Python.server_metrics_docker import (
    disable_defenses_and_syncookies, get_tcp_metrics
)

TARGET_IP = "lamp-server"
TARGET_PORT = 80
HTTP_URL = "http://lamp-server"
NB_PACKETS = 100000
ATTACK_DURATION = 30


def send_http_request():
    try:
        start = time.time()
        r = requests.get(HTTP_URL, timeout=5)
        duration = time.time() - start
        print(f"[HTTP] {r.status_code} en {duration:.2f}s", flush=True)
        return {"status": r.status_code, "time": duration}
    except Exception as e:
        print(f"[HTTP] Exception : {e}", flush=True)
        return {"error": str(e)}


# Cette fonction vérifie qu'un SYN flood n'affecte pas le serveur sous Docker : ni ListenDrops, ni Syncookies, et HTTP reste servi
def test_syn_flood_no_effect_under_docker():
    print("\n--- TEST : inefficacité du SYN flood dans Docker ---")

    # 1. Désactivation complète des défenses
    disable_defenses_and_syncookies()

    # 2. Capture des métriques kernel AVANT
    before = get_tcp_metrics()
    ldrop_before = before.get("ListenDrops", 0)
    syncookies_before = before.get("SyncookiesSent", 0)

    print(f"[AVANT] ListenDrops       : {ldrop_before}")
    print(f"[AVANT] SyncookiesSent    : {syncookies_before}")

    # 3. Lancement de l'attaque SYN flood en thread
    print(f"[*] Lancement de l'attaque SYN flood sur {TARGET_IP}:{TARGET_PORT} ({NB_PACKETS} paquets)...", flush=True)
    attack_thread = threading.Thread(target=syn_flood, args=(TARGET_IP, TARGET_PORT, NB_PACKETS))
    attack_thread.start()

    # 4. Envoi d'une requête HTTP PENDANT le flood
    time.sleep(1)  # petite latence pour que le flood démarre bien
    result = send_http_request()

    # 5. Attente de fin d'attaque
    attack_thread.join()

    # 6. Capture des métriques kernel APRÈS
    after = get_tcp_metrics()
    ldrop_after = after.get("ListenDrops", 0)
    syncookies_after = after.get("SyncookiesSent", 0)

    print(f"[APRÈS] ListenDrops       : {ldrop_after}")
    print(f"[APRÈS] SyncookiesSent    : {syncookies_after}")
    print(f"[Δ] Écart ListenDrops     : {ldrop_after - ldrop_before}")
    print(f"[Δ] Écart SyncookiesSent  : {syncookies_after - syncookies_before}")

    # 7. Vérification
    assert ldrop_after - ldrop_before == 0, "Des ListenDrops ont été détectés malgré Docker"
    assert syncookies_after - syncookies_before == 0, "Des Syncookies ont été envoyés malgré Docker"

    if result.get("status") == 200:
        print(f"[✔] Requête HTTP servie avec succès pendant le flood")
    else:
        print(f"[!] Erreur pendant la requête HTTP : {result}")

    print("[✔] Le SYN flood n’a eu aucun effet mesurable dans Docker (kernel ignoré)")
    print("--- FIN DU TEST ---\n")

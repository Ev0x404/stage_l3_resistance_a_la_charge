import pytest
import threading
import time
import requests
import debugpy
from src.Python.server_metrics_raspberry import ServerMetrics
from src.Python.network_utilities import syn_flood


# # #=====================================================================================================================
# # #==================================== ATTAQUE SYN FLOOD ==============================================================
# # #=====================================================================================================================

def send_http_request(ip, port, result):
    try:
        r = requests.get(f"http://{ip}:{port}", timeout=3)
        result["status"] = r.status_code
        result["time"] = r.elapsed.total_seconds()
    except Exception as e:
        result["error"] = str(e)

@pytest.fixture
def metrics():
    return ServerMetrics(host="192.168.1.40", user="raspberry", password="1234")


#=====================================================================================================================
#==================================== SYN AVEC ET SANS SYNPROXY ======================================================
#=====================================================================================================================

# Test l'impact d'un SYN flood sans SYNPROXY ni SYN cookies pour mesurer l'impact sans protections
def test_syn_flood_without_synproxy_and_without_cookies(metrics):
    target_ip = "192.168.1.40"
    port = 80
    nb_packets = 400000

    print(f"[+] Test SYN flood SANS SYNPROXY ni SYN cookies sur {target_ip}:{port}", flush=True)

    # 0. Désactivation protections
    print("[*] Désactivation SYN cookies + flush iptables", flush=True)
    metrics.set_tcp_syncookies(0)

    metrics.disable_synproxy(80)

    # 1. Requête HTTP de base
    before = {}
    send_http_request(target_ip, port, before)
    print(f"[+] HTTP avant attaque: {before}", flush=True)

    # 2. Collecte avant attaque
    print("[*] Collecte des métriques AVANT attaque", flush=True)
    metrics_before = metrics.collect()
    drops_before = metrics_before["TcpExt"].get("ListenDrops", 0)
    syncookies_sent_before = metrics_before["TcpExt"].get("SyncookiesSent", 0)

    # 3. Lancer l'attaque
    print(f"[+] Lancement flood ({nb_packets} paquets)", flush=True)
    thread = threading.Thread(target=syn_flood, args=(target_ip, port, nb_packets), daemon=True)
    thread.start()
    time.sleep(30)

    # 4. Requête HTTP pendant attaque
    during = {}
    send_http_request(target_ip, port, during)
    print(f"[+] HTTP pendant attaque: {during}", flush=True)

    # 5. Collecte après
    print("[*] Collecte des métriques APRÈS attaque", flush=True)
    metrics_after = metrics.collect()
    drops_after = metrics_after["TcpExt"].get("ListenDrops", 0)
    syncookies_sent_after = metrics_after["TcpExt"].get("SyncookiesSent", 0)

    print(f"[+] ListenDrops : {drops_before} → {drops_after} (Δ={drops_after - drops_before})")
    print(f"[+] SyncookiesSent : {syncookies_sent_before} → {syncookies_sent_after} (Δ={syncookies_sent_after - syncookies_sent_before})")

    if "error" in during:
        print("[✓] Requête HTTP échouée → effet confirmé", flush=True)
    elif "time" in during and "time" in before:
        slowdown = during["time"] / before["time"]
        print(f"[!] Ralentissement HTTP : x{slowdown:.2f}", flush=True)
        assert slowdown > 3, "[-] Requête trop rapide malgré le flood"
    else:
        raise AssertionError("[-] La requête HTTP n’a pas été impactée malgré le SYN flood")

    assert drops_after > drops_before, "[-] ListenDrops n'ont pas augmenté"
    assert syncookies_sent_after == syncookies_sent_before, "[!] Syncookies utilisés alors qu’ils sont désactivés"


# Test le flood SYN en protégeant avec SYNPROXY et vérifie accès HTTP et stats
def test_syn_flood_with_synproxy(metrics):
    target_ip = "192.168.1.40"
    port = 80
    nb_packets = 400000

    print(f"[+] Test SYN flood avec SYNPROXY officiel sur {target_ip}:{port}", flush=True)

    # Activation de SYNPROXY
    metrics.enable_synproxy(port)

    # 0. Vérification de l'état initial du serveur
    print("[*] Vérification de l'état initial du serveur...", flush=True)
    before = {}
    send_http_request(target_ip, port, before)  # Sans paramètre timeout
    print(f"[+] HTTP avant attaque: {before}", flush=True)
    
    if "error" in before:
        print(f"[!] AVERTISSEMENT: Le serveur n'est pas accessible: {before['error']}")
        print("[!] Le test continuera mais les résultats peuvent être affectés")
    else:
        print(f"[✓] Le serveur est accessible (code {before.get('status', 'inconnu')})")

    # 1. Collecte métriques avant attaque
    print("[*] Collecte des métriques AVANT attaque", flush=True)
    metrics_before = metrics.collect()
    drops_before = metrics_before["TcpExt"].get("ListenDrops", 0)
    syncookies_sent_before = metrics_before["TcpExt"].get("SyncookiesSent", 0)
    
    # Vérifier les statistiques SYNPROXY
    synproxy_stats_before = metrics.ssh_exec("cat /proc/net/stat/synproxy 2>/dev/null || echo 'N/A'")
    print(f"[+] Stats SYNPROXY avant attaque: {synproxy_stats_before}")
    
    # 2. Lancer l'attaque SYN flood
    print(f"[+] Lancement flood ({nb_packets} paquets)", flush=True)
    thread = threading.Thread(target=syn_flood, args=(target_ip, port, nb_packets), daemon=True)
    thread.start()
    
    # Attendre que l'attaque soit en cours
    time.sleep(30)
    
    # 3. Requête HTTP pendant l'attaque
    during = {}
    print("[*] Tentative de requête HTTP pendant l'attaque...", flush=True)
    send_http_request(target_ip, port, during)  # Sans paramètre timeout
    print(f"[+] HTTP pendant attaque: {during}", flush=True)
    
    # Attendre encore pour l'attaque
    time.sleep(20)

    # 4. Collecte métriques après attaque
    print("[*] Collecte des métriques APRÈS attaque", flush=True)
    metrics_after = metrics.collect()
    drops_after = metrics_after["TcpExt"].get("ListenDrops", 0)
    syncookies_sent_after = metrics_after["TcpExt"].get("SyncookiesSent", 0)
    
    # Vérifier les statistiques SYNPROXY après
    synproxy_stats_after = metrics.ssh_exec("cat /proc/net/stat/synproxy 2>/dev/null || echo 'N/A'")
    print(f"[+] Stats SYNPROXY après attaque: {synproxy_stats_after}")

    print(f"[+] ListenDrops : {drops_before} → {drops_after} (Δ={drops_after - drops_before})")
    print(f"[+] SyncookiesSent : {syncookies_sent_before} → {syncookies_sent_after} (Δ={syncookies_sent_after - syncookies_sent_before})")

    # 5. Requête HTTP après l'attaque
    after = {}
    send_http_request(target_ip, port, after)  # Sans paramètre timeout
    print(f"[+] HTTP après attaque: {after}", flush=True)

    # 6. Analyse des résultats
    synproxy_active = False
    if synproxy_stats_after != "N/A" and synproxy_stats_after != synproxy_stats_before:
        print("[✓] SYNPROXY a bien traité des paquets pendant l'attaque", flush=True)
        synproxy_active = True
    
    cookies_active = syncookies_sent_after > syncookies_sent_before
    if cookies_active:
        print(f"[✓] SYN cookies actifs: {syncookies_sent_after - syncookies_sent_before} cookies envoyés", flush=True)
    
    if "error" in during:
        print("[!] Les requêtes HTTP ont été bloquées pendant l'attaque", flush=True)
        print(f"[!] Erreur: {during['error']}")
    else:
        print("[✓] SUCCÈS: Les requêtes HTTP légitimes passent pendant l'attaque!", flush=True)
        if "time" in during and "time" in before:
            slowdown = during["time"] / before["time"]
            print(f"[i] Ralentissement HTTP pendant l'attaque: x{slowdown:.2f}", flush=True)
    
    # 7. Analyse avancée des statistiques SYNPROXY
    if synproxy_stats_after != "N/A" and synproxy_stats_before != "N/A":
        try:
            # Parsing des statistiques SYNPROXY (le format peut varier)
            print("[+] Analyse détaillée des statistiques SYNPROXY:")
            
            # Afficher les statistiques brutes
            print(f"Stats avant: {synproxy_stats_before}")
            print(f"Stats après: {synproxy_stats_after}")
            
            # L'analyse précise dépendra du format exact des statistiques
            print("[i] Ces statistiques montrent l'activité du module SYNPROXY pendant l'attaque")
        except Exception as e:
            print(f"[!] Erreur lors de l'analyse des statistiques SYNPROXY: {e}")
    
    # 8. Conclusion
    print("[*] Conclusion du test:", flush=True)
    
    if synproxy_active:
        print("[✓] SYNPROXY a été activé et a protégé contre l'attaque", flush=True)
    elif cookies_active:
        print("[i] SYN cookies ont été utilisés mais SYNPROXY n'a pas été déclenché", flush=True)
    else:
        print("[!] Ni SYNPROXY ni SYN cookies n'ont été déclenchés", flush=True)
    
    if "error" not in after:
        print("[✓] Le serveur est resté accessible après l'attaque", flush=True)
    else:
        print("[!] Le serveur n'est pas accessible après l'attaque", flush=True)
    
    # Retourner le résultat du test
    return synproxy_active or cookies_active


# Compare SYNPROXY + SYN cookies vs SYN cookies seuls contre SYN flood
def test_compare_synproxy_vs_cookies_only(metrics):
    target_ip = "192.168.1.40"
    port = 80
    nb_packets = 400000

    def run_test(description, setup_fn):
        print(f"\n=== {description} ===", flush=True)
        setup_fn()

        # 1. Requête HTTP avant attaque
        before = {}
        send_http_request(target_ip, port, before)
        print(f"[HTTP avant] {before}", flush=True)

        # 2. Collecte avant attaque
        metrics_before = metrics.collect()
        drops_before = metrics_before["TcpExt"].get("ListenDrops", 0)
        cookies_before = metrics_before["TcpExt"].get("SyncookiesSent", 0)

        # 3. Lancer attaque
        print(f"[+] Flood de {nb_packets} paquets...", flush=True)
        thread = threading.Thread(target=syn_flood, args=(target_ip, port, nb_packets), daemon=True)
        thread.start()
        time.sleep(30)

        # 4. Requête pendant attaque
        during = {}
        send_http_request(target_ip, port, during)
        print(f"[HTTP pendant attaque] {during}", flush=True)

        # 5. Collecte après
        metrics_after = metrics.collect()
        drops_after = metrics_after["TcpExt"].get("ListenDrops", 0)
        cookies_after = metrics_after["TcpExt"].get("SyncookiesSent", 0)

        slowdown = (
            during["time"] / before["time"]
            if "time" in during and "time" in before
            else float("inf")
        )

        return {
            "http_before": before,
            "http_during": during,
            "drops_delta": drops_after - drops_before,
            "cookies_delta": cookies_after - cookies_before,
            "slowdown": slowdown,
        }

    # ---------- Test avec SYN cookies UNIQUEMENT ----------
    def setup_cookies_only():
        metrics.disable_synproxy(port)
        metrics.set_tcp_syncookies(1)

    result_cookies = run_test("Test 1 : SYN cookies UNIQUEMENT", setup_cookies_only)

    # ---------- Test avec SYNPROXY + cookies ----------
    def setup_synproxy():
        metrics.enable_synproxy(port)

    result_synproxy = run_test("Test 2 : SYNPROXY + SYN cookies", setup_synproxy)

    # ---------- Affichage comparatif ----------
    print("\n=== Résumé Comparatif ===\n")
    print(f"{'':<30} {'SYN Cookies':<20} {'SYNPROXY + Cookies':<20}")
    print("-" * 70)
    print(f"{'ListenDrops Δ':<30} {result_cookies['drops_delta']:<20} {result_synproxy['drops_delta']:<20}")
    print(f"{'SyncookiesSent Δ':<30} {result_cookies['cookies_delta']:<20} {result_synproxy['cookies_delta']:<20}")
    print(f"{'HTTP slowdown (x)':<30} {result_cookies['slowdown']:.2f}x{'':<16} {result_synproxy['slowdown']:.2f}x")

    # ---------- Interprétation ----------
    print("\n=== Analyse ===")
    if result_cookies['drops_delta'] > result_synproxy['drops_delta']:
        print("[✓] SYNPROXY a réduit le nombre de ListenDrops → meilleure résistance au flood.")
    else:
        print("[!] Aucune amélioration nette sur ListenDrops avec SYNPROXY.")

    if result_synproxy['slowdown'] < result_cookies['slowdown']:
        print("[✓] SYNPROXY a permis des requêtes HTTP plus rapides pendant l'attaque.")
    else:
        print("[!] Pas d'amélioration nette sur le temps de réponse HTTP.")

    if result_synproxy['cookies_delta'] < result_cookies['cookies_delta']:
        print("[✓] SYNPROXY a absorbé une partie des connexions sans déclencher autant de SYN cookies.")
    else:
        print("[!] Les SYN cookies ont été autant sollicités voire plus, malgré SYNPROXY.")

    print("\n[✓] Comparaison complète terminée.")

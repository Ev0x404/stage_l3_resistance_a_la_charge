import threading
import time
import requests
import socket
from src.Python.server_metrics_raspberry import ServerMetrics
from src.Python.network_utilities import run_slowloris_attack_thread

# Constantes globales
RASPBERRY_IP = "192.168.1.40"
RASPBERRY_USER = "raspberry"
RASPBERRY_PASS = "1234"
TARGET_URL = f"http://{RASPBERRY_IP}/index.php"
TARGET_PORT = 80
TIMEOUT = 5
BANTIME = 30

# Fonctions auxiliaires pour tous les tests
def is_http_reachable(url=TARGET_URL, timeout=TIMEOUT):
    try:
        r = requests.get(url, timeout=timeout)
        print(f"[DEBUG] Status: {r.status_code}, Body: {repr(r.text)}")
        return r.status_code == 200 and "OK" in r.text.strip()
    except Exception as e:
        print(f"[DEBUG] Exception dans is_http_reachable: {e}")
        return False


def get_local_ipv4():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


# Test Fail2Ban avec requêtes HTTP simultanées pour déclencher le ban
def test_fail2ban_ban_parallel_threads():
    ban_expected_after = 100
    total_requests = ban_expected_after + 50  # pour s'assurer du déclenchement

    print("\n--- DÉBUT DU TEST Fail2Ban HTTP PAR THREADS ---")

    # Initialisation SSH
    metrics = ServerMetrics(host=RASPBERRY_IP, user=RASPBERRY_USER, password=RASPBERRY_PASS)
    my_ip = get_local_ipv4()
    print(f"[i] IP locale détectée: {my_ip}")

    # Configuration Fail2Ban
    print("[*] Activation de Fail2Ban...")
    result = metrics.enable_fail2ban(bantime=BANTIME, findtime=60, maxretry=ban_expected_after)
    print(f"[+] Résultat: {result}")
    
    initial_metrics = metrics.get_fail2ban_metrics()
    print(f"[#] Fail2Ban actif: {initial_metrics['active']} | Jails: {initial_metrics['jails']}")
    assert initial_metrics['active'], "Fail2Ban n'est pas actif"

    # Vérification accès initial
    assert is_http_reachable(), "index.php inaccessible avant le test"
    print("[+] Le serveur est accessible")

    # Fonction de requête HTTP par thread
    def send_request(i):
        try:
            r = requests.get(TARGET_URL, timeout=5, headers={"Connection": "close"})
            print(f"[Thread {i+1}] {r.status_code}")
        except Exception as e:
            print(f"[Thread {i+1}] EXCEPTION: {e}")

    # Lancer les threads
    print(f"[>] Lancement de {total_requests} requêtes simultanées via threads...")
    threads = []
    for i in range(total_requests):
        t = threading.Thread(target=send_request, args=(i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # Vérification du bannissement
    print("[*] Vérification après le flood...")
    time.sleep(1)
    banned = not is_http_reachable()
    assert banned, "Fail2Ban ne semble pas avoir bloqué l'IP"
    print("[S] Bannissement détecté avec succès")

    # Vérifier dans les logs
    metrics_after = metrics.get_fail2ban_metrics()
    was_banned = metrics.was_ip_banned_by_fail2ban(my_ip)

    print(f"[#] Total bans: {metrics_after['total_banned']}")
    assert was_banned, f"IP {my_ip} non retrouvée dans les logs Fail2Ban"

    # Attente du déban
    print(f"[~] Attente de {BANTIME} sec pour laisser expirer le ban...")
    time.sleep(BANTIME + 5)

    assert is_http_reachable(), "Service non restauré après le bannissement"
    print(f"[+] IP {my_ip} confirmée comme bannie et service restauré ensuite")

    print("--- FIN DU TEST ---\n")


# Test Fail2Ban pour attaque Slowloris et vérification du blocage et déban.
def test_fail2ban_slowloris():
    connections = 150
    attack_duration = 30
    
    print("\n--- DÉBUT DU TEST Fail2Ban contre attaque Slowloris ---")

    # Initialiser la connexion SSH
    metrics = ServerMetrics(host=RASPBERRY_IP, user=RASPBERRY_USER, password=RASPBERRY_PASS)
    
    # Obtenir l'adresse IP locale
    my_ip = get_local_ipv4()
    print(f"[i] IP locale détectée: {my_ip}")
    
    # 1. Configurer Fail2Ban pour détecter les attaques Slowloris
    # Utiliser la méthode dédiée dans ServerMetrics
    print("[*] Configuration de Fail2Ban pour détecter les attaques Slowloris...")
    result = metrics.configure_fail2ban_for_slowloris(bantime=BANTIME, findtime=30, maxretry=5)
    print(f"[+] Résultat: {result}")
    
    # Vérifier que Fail2Ban est bien configuré
    initial_metrics = metrics.get_fail2ban_metrics()
    print(f"[#] État initial de Fail2Ban: actif={initial_metrics['active']}, jails={initial_metrics['jails']}")
    assert initial_metrics['active'], "Fail2Ban n'est pas actif"
    
    # 2. Vérifier accessibilité initiale
    assert is_http_reachable(), "Échec : index.php inaccessible avant le test"
    print("[+] Le serveur web est accessible")

    # 3. Lancer l'attaque Slowloris dans un thread séparé
    print(f"[>] Lancement de l'attaque Slowloris avec {connections} connexions pour {attack_duration} secondes...")
    attack_thread = run_slowloris_attack_thread(RASPBERRY_IP, TARGET_PORT, connections, attack_duration)
    
    # 4. Surveiller l'accessibilité du serveur pendant l'attaque
    print("[?] Surveillance de l'accessibilité du serveur pendant l'attaque...")
    banned = False
    start_time = time.time()
    
    while time.time() - start_time < attack_duration + 15:  # Attendre l'attaque + 15 secondes
        time.sleep(5)  # Vérifier toutes les 5 secondes
        
        # Vérifier si le serveur est encore accessible
        server_reachable = is_http_reachable()
        elapsed = time.time() - start_time
        
        if not server_reachable:
            print(f"[!] Serveur inaccessible après {elapsed:.1f} secondes - possible congestion due à Slowloris")
        else:
            print(f"[+] Serveur toujours accessible après {elapsed:.1f} secondes")
        
        # Vérifier si Fail2Ban a banni notre IP
        fail2ban_metrics = metrics.get_fail2ban_metrics()
        if my_ip in fail2ban_metrics.get('banned_ips', []):
            print(f"[S] IP {my_ip} bannie par Fail2Ban après {elapsed:.1f} secondes!")
            banned = True
            break
    
    # 5. Attendre que l'attaque se termine
    attack_thread.join(timeout=5)
    
    # 6. Vérifier les métriques finales de Fail2Ban
    final_metrics = metrics.get_fail2ban_metrics()
    print(f"""[#] Métriques finales de Fail2Ban:
    - Total bannissements: {final_metrics['total_banned']}
    - IP actuellement bannies: {final_metrics['current_banned']}
    - Liste des jails: {final_metrics['jails']}
    """)
    
    # 7. Vérifier dans les logs si notre IP a été bannie
    was_banned = metrics.was_ip_banned_by_fail2ban(my_ip)
    if was_banned:
        print(f"[+] IP {my_ip} confirmée comme bannie dans les logs Fail2Ban")
    else:
        print(f"[!] IP {my_ip} non retrouvée dans les logs Fail2Ban")
    
    # 8. Si l'IP n'a pas été bannie, attendre un peu plus et revérifier
    if not was_banned and not banned:
        print("[~] Attente supplémentaire de 15 secondes pour voir si Fail2Ban réagit...")
        time.sleep(15)
        
        # Revérifier si l'IP a été bannie
        was_banned = metrics.was_ip_banned_by_fail2ban(my_ip)
        if was_banned:
            print(f"[+] IP {my_ip} finalement bannie après attente supplémentaire")
        else:
            print(f"[-] IP {my_ip} toujours pas bannie - Fail2Ban n'a pas détecté l'attaque Slowloris")
    
    # 9. Attendre que le ban expire si nécessaire
    if banned or was_banned:
        print(f"[~] Attente de {BANTIME} secondes pour que le ban expire...")
        time.sleep(BANTIME + 5)  # +5 pour être sûr
        
        # Vérifier que le service est de nouveau accessible
        service_restored = is_http_reachable()
        print(f"[^] Service restauré après bannissement: {service_restored}")
        assert service_restored, "Le service n'est pas restauré après expiration du bannissement"
    
    # 10. Assertion finale pour pytest
    assert banned or was_banned, "Fail2Ban n'a pas détecté l'attaque Slowloris"
    
    # Conclusion du test
    if banned or was_banned:
        print("[+] Fail2Ban a détecté et contré l'attaque Slowloris avec succès!")
    else:
        print("[-] Fail2Ban n'a pas détecté l'attaque Slowloris - configuration à améliorer!")
    
    print("--- FIN DU TEST ---\n")


# Test Fail2Ban avec requête non-HTTP sur le port 80 pour observer le comportement du serveur
# Il renvoie des erreurs comme quoi les requêtes sont mal formées mais bloque bien l'ip tout de même
def test_fail2ban_random_requests_on_port_80():
    print("\n--- DÉBUT DU TEST SUR PORT 80 ---")

    metrics = ServerMetrics(host=RASPBERRY_IP, user=RASPBERRY_USER, password=RASPBERRY_PASS)
    my_ip = get_local_ipv4()
    print(f"[i] IP locale détectée: {my_ip}")

    print("[*] Activation de Fail2Ban avec configuration standard...")
    metrics.enable_fail2ban(bantime=BANTIME, findtime=60, maxretry=5)

    # Envoi de données non valides
    def send_garbage(i):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((RASPBERRY_IP, TARGET_PORT))
            garbage = b"#$%^&*()_+ INVALID HTTP\r\n\r\n"
            s.sendall(garbage)
            try:
                response = s.recv(1024).decode("utf-8", errors="ignore")
                if response.startswith("HTTP/"):
                    status_line = response.split("\r\n")[0]
                    print(f"[Thread {i+1}] {status_line}")
                else:
                    print(f"[Thread {i+1}] Réponse non-HTTP")
            except socket.timeout:
                print(f"[Thread {i+1}] Pas de réponse (timeout)")
            s.close()
        except Exception as e:
            print(f"[Thread {i+1}] EXCEPTION: {e}")

    print("[>] Envoi de 50 requêtes invalides vers le port 80...")
    threads = []
    for i in range(50):
        t = threading.Thread(target=send_garbage, args=(i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print("[*] Attente pour laisser Fail2Ban analyser les logs...")
    time.sleep(5)

    # Vérification bannissement
    banned = metrics.was_ip_banned_by_fail2ban(my_ip)
    if banned:
        print(f"[S] IP {my_ip} bannie suite aux données invalides !")
    else:
        print(f"[!] IP {my_ip} non bannie malgré les données brutes")

    print(f"[~] Attente de {BANTIME} sec pour expiration éventuelle du ban...")
    time.sleep(BANTIME + 5)

    print("--- FIN DU TEST ---\n")
    assert True  # Test exploratoire


# Test Fail2Ban + NGINX rate limiting pour bannir après flood HTTP
def test_fail2ban_ban_parallel_threads_with_nginx_ratelimit():
    ban_expected_after = 100
    total_requests = ban_expected_after + 50  # pour s'assurer du déclenchement

    print("\n--- DÉBUT DU TEST Fail2Ban + NGINX Rate Limiting HTTP PAR THREADS ---")

    # Initialisation SSH
    metrics = ServerMetrics(host=RASPBERRY_IP, user=RASPBERRY_USER, password=RASPBERRY_PASS)
    my_ip = get_local_ipv4()
    print(f"[i] IP locale détectée: {my_ip}")

    # Configuration Fail2Ban
    print("[*] Activation de Fail2Ban...")
    result = metrics.enable_fail2ban(bantime=BANTIME, findtime=60, maxretry=ban_expected_after)
    print(f"[+] Résultat: {result}")

    # Activation rate limiting NGINX
    print("[*] Activation rate limiting NGINX...")
    metrics.enable_nginx_ratelimit()

    initial_metrics = metrics.get_fail2ban_metrics()
    print(f"[#] Fail2Ban actif: {initial_metrics['active']} | Jails: {initial_metrics['jails']}")
    assert initial_metrics['active'], "Fail2Ban n'est pas actif"

    # Vérification accès initial
    assert is_http_reachable(), "index.php inaccessible avant le test"
    print("[+] Le serveur est accessible")

    # Fonction de requête HTTP par thread
    def send_request(i):
        try:
            r = requests.get(TARGET_URL, timeout=5, headers={"Connection": "close"})
            print(f"[Thread {i+1}] {r.status_code}")
        except Exception as e:
            print(f"[Thread {i+1}] EXCEPTION: {e}")

    # Lancer les threads
    print(f"[>] Lancement de {total_requests} requêtes simultanées via threads...")
    threads = []
    for i in range(total_requests):
        t = threading.Thread(target=send_request, args=(i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # Vérification du bannissement
    print("[*] Vérification après le flood...")
    time.sleep(1)
    banned = not is_http_reachable()
    assert banned, "Fail2Ban ne semble pas avoir bloqué l'IP"
    print("[S] Bannissement détecté avec succès")

    # Vérifier dans les logs
    metrics_after = metrics.get_fail2ban_metrics()
    was_banned = metrics.was_ip_banned_by_fail2ban(my_ip)

    print(f"[#] Total bans: {metrics_after['total_banned']}")
    assert was_banned, f"IP {my_ip} non retrouvée dans les logs Fail2Ban"

    # Attente du déban
    print(f"[~] Attente de {BANTIME} sec pour laisser expirer le ban...")
    time.sleep(BANTIME + 5)

    assert is_http_reachable(), "Service non restauré après le bannissement"
    print(f"[+] IP {my_ip} confirmée comme bannie et service restauré ensuite")

    # Nettoyage rate limiting
    print("[*] Désactivation du rate limiting NGINX")
    metrics.disable_nginx_ratelimit()

    print("--- FIN DU TEST ---\n")

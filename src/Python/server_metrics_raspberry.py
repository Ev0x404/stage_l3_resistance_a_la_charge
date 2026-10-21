#####################################
## Classe métriques pour raspberry ##
#####################################

import time
import paramiko
import json
import subprocess

import requests

class ServerMetrics:
    def __init__(self, host, user, password):
        self.host = host
        self.user = user
        self.password = password
    
    # Permet de faire exécuter une commande en ssh
    def ssh_exec(self, command: str):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(self.host, username=self.user, password=self.password)
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode().strip()
        ssh.close()
        return output    
    

    def collect(self):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(self.host, username=self.user, password=self.password)

        stdin, stdout, stderr = ssh.exec_command("cat /proc/net/netstat")
        output = stdout.read().decode()
        ssh.close()

        return self._parse_netstat(output)

    def _parse_netstat(self, text):
        lines = text.strip().splitlines()
        metrics = {}
        i = 0
        while i < len(lines) - 1:
            header_line = lines[i].strip()
            value_line = lines[i + 1].strip()
            if not header_line or not value_line:
                i += 1
                continue

            header_parts = header_line.split()
            value_parts = value_line.split()

            # Vérifie que les deux lignes commencent par le même "label", ex: "TcpExt:"
            if header_parts[0].endswith(":") and header_parts[0] == value_parts[0]:
                key = header_parts[0][:-1]  # Ex: "TcpExt:"
                headers = header_parts[1:]
                values = list(map(int, value_parts[1:]))
                if len(headers) == len(values):
                    metrics[key] = dict(zip(headers, values))
                i += 2
            else:
                i += 1  # skip ligne isolée ou invalide
        return metrics

    # Fonction permettant d'activer/désactiver les syn cookies (0 -> désactivés | 1 -> activés)
    def set_tcp_syncookies(self, value: int):
        cmd = f"sudo sysctl -w net.ipv4.tcp_syncookies={value}"
        return self.ssh_exec(cmd)
    
    
    #-------------------------------------------------------------------------------------
    #--------------------------------- SYNPROXY ------------------------------------------
    #-------------------------------------------------------------------------------------

    def enable_synproxy(self, port):
        print("[*] Activation SYNPROXY selon les 6 étapes officielles...")

        # 0. Détection de l'interface réseau
        iface = self.ssh_exec("ip route get 8.8.8.8 | awk '/dev/ {print $5}'")

        # 1. Chargement des modules nécessaires
        self.ssh_exec("sudo modprobe nf_synproxy_core")
        self.ssh_exec("sudo modprobe nf_conntrack")

        # 2. Étape 1 : empêcher création d'entrées conntrack pour les SYN
        self.ssh_exec("sudo iptables -F")
        self.ssh_exec("sudo iptables -t raw -F")
        self.ssh_exec(f"sudo iptables -t raw -I PREROUTING -i {iface} -p tcp -m tcp --syn --dport {port} -j CT --notrack")

        # 3. Étape 2 : activer un suivi de connexion strict
        self.ssh_exec("sudo sysctl -w net.netfilter.nf_conntrack_tcp_loose=0")

        # 4. Étape 3 : configurer la cible SYNPROXY
        self.ssh_exec(f"sudo iptables -A INPUT -i {iface} -p tcp -m tcp --dport {port} -m state --state INVALID,UNTRACKED "
                    f"-j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460")

        # 5. Étape 4 : drop des paquets INVALID
        self.ssh_exec("sudo iptables -A INPUT -m state --state INVALID -j DROP")

        # 6. Étape 5 : activer les horodatages TCP
        self.ssh_exec("sudo sysctl -w net.ipv4.tcp_timestamps=1")

        # 7. Étape 6 : optimisation conntrack
        if "No such file" not in self.ssh_exec("sudo test -f /sys/module/nf_conntrack/parameters/hashsize || echo 'No such file'"):
            self.ssh_exec("sudo bash -c 'echo 131072 > /sys/module/nf_conntrack/parameters/hashsize'")
        self.ssh_exec("sudo sysctl -w net.netfilter.nf_conntrack_max=262144")

        # 8. Étapes supplémentaires
        self.ssh_exec("sudo iptables -I INPUT 1 -p tcp --dport 22 -j ACCEPT")  # SSH
        self.ssh_exec("sudo iptables -I INPUT 1 -i lo -j ACCEPT")              # Loopback
        self.ssh_exec("sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT")
        self.ssh_exec(f"sudo iptables -A INPUT -p tcp --dport {port} -m state --state NEW -j ACCEPT")

        print("[✓] SYNPROXY activé avec succès sur le port", port)

    
    def disable_synproxy(self, port):
        print("[*] Désactivation complète de SYNPROXY...")

        # 1. Flush complet iptables (table filter + raw)
        self.ssh_exec("sudo iptables -F")
        self.ssh_exec("sudo iptables -X")
        self.ssh_exec("sudo iptables -t raw -F")
        self.ssh_exec("sudo iptables -t raw -X")

        # 2. (Optionnel) Reset conntrack stricte si nécessaire
        self.ssh_exec("sudo sysctl -w net.netfilter.nf_conntrack_tcp_loose=1")

        # 3. Désactivation des SYN cookies
        self.ssh_exec("sudo sysctl -w net.ipv4.tcp_syncookies=0")

        # 4. Autoriser les connexions nécessaires minimales
        self.ssh_exec("sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT")  # SSH
        self.ssh_exec("sudo iptables -A INPUT -i lo -j ACCEPT")              # Loopback
        self.ssh_exec("sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT")

        # 5. Ne pas bloquer le port HTTP pour le test sans protection
        self.ssh_exec(f"sudo iptables -A INPUT -p tcp --dport {port} -j ACCEPT")

        print("[✓] SYNPROXY désactivé et environnement iptables nettoyé")
        
        
        
    #-------------------------------------------------------------------------------------
    #--------------------------------- FAIL2BAN ------------------------------------------
    #-------------------------------------------------------------------------------------
        
    def enable_fail2ban(self, bantime=30, findtime=60, maxretry=100):
        print("[*] Activation de Fail2Ban pour la protection HTTP...")
        
        # 1. S'assurer que fail2ban est installé
        install_status = self.ssh_exec("dpkg -l | grep -q fail2ban || sudo apt-get install -y fail2ban")
        
        # 2. Désactiver la jail sshd pour éviter les erreurs
        self.ssh_exec("""
        sudo mkdir -p /etc/fail2ban
        sudo bash -c 'echo "[sshd]
    enabled = false" > /etc/fail2ban/jail.local'
        """)
        
        # 3. Configurer la jail nginx-too-many-requests
        self.ssh_exec(f"""
        sudo mkdir -p /etc/fail2ban/jail.d
        sudo bash -c 'echo "[nginx-too-many-requests]
    enabled = true
    filter = nginx-too-many-requests
    port = http,https
    logpath = /var/log/nginx/access.log
    maxretry = {maxretry}
    findtime = {findtime}
    bantime = {bantime}
    action = iptables[name=HTTP, port=http, protocol=tcp]" > /etc/fail2ban/jail.d/nginx-too-many-requests.local'
        """)
        
        # 4. Créer le filtre pour détecter les requêtes
        self.ssh_exec("""
        sudo mkdir -p /etc/fail2ban/filter.d
        sudo bash -c 'echo "[Definition]
    failregex = ^<HOST> -.*\\\"(GET|POST).*" > /etc/fail2ban/filter.d/nginx-too-many-requests.conf'
        """)
        
        # 5. S'assurer que le répertoire de logs existe
        self.ssh_exec("sudo mkdir -p /var/log/nginx")
        self.ssh_exec("sudo touch /var/log/nginx/access.log")
        self.ssh_exec("sudo chmod 644 /var/log/nginx/access.log")
        
        # 6. Redémarrer Fail2Ban
        self.ssh_exec("sudo systemctl restart fail2ban")
        
        # 7. Vérifier que Fail2Ban est bien démarré
        status = self.ssh_exec("sudo systemctl is-active fail2ban")
        
        # 8. Récupérer les informations sur la jail
        jail_status = self.ssh_exec("sudo fail2ban-client status nginx-too-many-requests")
        
        return f"Fail2Ban activé avec statut: {status}\nConfiguration jail: {jail_status}"


    def disable_fail2ban(self):
        print("[*] Désactivation de Fail2Ban...")
        
        # 1. Débannir toutes les IP
        self.ssh_exec("sudo fail2ban-client unban --all 2>/dev/null || true")
        
        # 2. Arrêter le service
        self.ssh_exec("sudo systemctl stop fail2ban")
        
        # 3. Supprimer les règles iptables créées par Fail2Ban
        self.ssh_exec("sudo iptables -D INPUT -j f2b-nginx-too-many-requests 2>/dev/null || true")
        self.ssh_exec("sudo iptables -F f2b-nginx-too-many-requests 2>/dev/null || true")
        self.ssh_exec("sudo iptables -X f2b-nginx-too-many-requests 2>/dev/null || true")
        
        # 4. Vérifier que Fail2Ban est bien arrêté
        status = self.ssh_exec("sudo systemctl is-active fail2ban")
        
        return f"Fail2Ban désactivé avec statut: {status}"


    def configure_fail2ban_for_slowloris(self, bantime=60, findtime=30, maxretry=5):
        print("[*] Configuration de Fail2Ban pour détecter les attaques Slowloris...")
        
        # 1. S'assurer que Fail2Ban est bien installé et fonctionnel
        self.ssh_exec("sudo apt-get update && sudo apt-get install -y fail2ban")
        
        # 2. Arrêter complètement Fail2Ban pour un état propre
        self.ssh_exec("sudo systemctl stop fail2ban")
        time.sleep(2)
        
        # 3. Désactiver la jail sshd pour éviter les erreurs
        self.ssh_exec("""
        sudo mkdir -p /etc/fail2ban
        sudo bash -c 'echo "[sshd]
    enabled = false" > /etc/fail2ban/jail.local'
        """)
        
        # 4. Configuration des jails : d'abord la jail normale HTTP
        self.ssh_exec(f"""
        sudo mkdir -p /etc/fail2ban/jail.d
        sudo bash -c 'echo "[nginx-too-many-requests]
    enabled = true
    filter = nginx-too-many-requests
    port = http,https
    logpath = /var/log/nginx/access.log
    maxretry = {maxretry*2}
    findtime = {findtime*2}
    bantime = {bantime}
    action = iptables[name=HTTP, port=http, protocol=tcp]" > /etc/fail2ban/jail.d/nginx-too-many-requests.local'
        """)
        
        # 5. Créer le filtre pour les requêtes HTTP standard
        self.ssh_exec("""
        sudo mkdir -p /etc/fail2ban/filter.d
        sudo bash -c 'echo "[Definition]
    failregex = ^<HOST> -.*\\"(GET|POST).*" > /etc/fail2ban/filter.d/nginx-too-many-requests.conf'
        """)
        
        # 6. Configurer la jail spécifique pour Slowloris
        self.ssh_exec(f"""
        sudo bash -c 'echo "[nginx-slowloris]
    enabled = true
    filter = nginx-slowloris
    port = http,https
    logpath = /var/log/nginx/access.log
    maxretry = {maxretry}
    findtime = {findtime}
    bantime = {bantime}
    action = iptables[name=HTTP, port=http, protocol=tcp]" > /etc/fail2ban/jail.d/nginx-slowloris.local'
        """)
        
        # 7. Créer le filtre pour Slowloris
        self.ssh_exec("""
        sudo bash -c 'echo "[Definition]
    failregex = ^<HOST> -.*\\"(GET|POST).* (408|400|431|414)
                ^<HOST> -.*\\"(GET|HEAD|POST).*\\" 4[0-9][0-9]" > /etc/fail2ban/filter.d/nginx-slowloris.conf'
        """)
        
        # 8. Vérifier que les logs existent
        self.ssh_exec("sudo mkdir -p /var/log/nginx")
        self.ssh_exec("sudo touch /var/log/nginx/access.log")
        self.ssh_exec("sudo chmod 644 /var/log/nginx/access.log")
        
        # 9. Redémarrer Fail2Ban proprement
        self.ssh_exec("sudo systemctl daemon-reload")
        self.ssh_exec("sudo systemctl restart fail2ban")
        
        # 10. Attendre que le service démarre complètement
        print("[*] Attente du démarrage complet de Fail2Ban...")
        time.sleep(5)
        
        # 11. Vérifier que le service est bien démarré
        service_status = self.ssh_exec("sudo systemctl is-active fail2ban")
        if service_status.strip() != "active":
            print(f"[!] ERREUR: Fail2Ban n'est pas actif. Statut: {service_status}")
            # Tenter une solution
            self.ssh_exec("sudo fail2ban-client ping")
            self.ssh_exec("sudo systemctl restart fail2ban")
            time.sleep(5)
        
        # 12. Vérifier les jails configurées
        jails = self.ssh_exec("sudo fail2ban-client status | grep 'Jail list' | sed 's/^.*Jail list://g'").strip()
        
        # 13. Diagnostic approfondi si toujours pas actif
        if not jails:
            print("[!] ERREUR: Aucune jail trouvée. Diagnostic avancé...")
            
            # Vérifier les logs pour diagnostiquer le problème
            fail2ban_log = self.ssh_exec("sudo tail -n 30 /var/log/fail2ban.log")
            print(f"[!] Logs Fail2Ban: {fail2ban_log}")
            
            # Vérifier la configuration
            config_test = self.ssh_exec("sudo fail2ban-client -d")
            print(f"[!] Test de configuration: {config_test}")
            
            # Relancer manuellement avec options de debug
            self.ssh_exec("sudo systemctl stop fail2ban")
            self.ssh_exec("sudo fail2ban-server -xvf start")
        
        return f"Configuration de Fail2Ban pour Slowloris terminée. Jails: {jails}"


    def get_fail2ban_metrics(self):
        # Vérifier si Fail2Ban est actif
        is_active = self.ssh_exec("sudo systemctl is-active fail2ban").strip() == "active"
        
        if not is_active:
            return {
                "active": False,
                "jails": [],
                "total_banned": 0,
                "current_banned": 0
            }
        
        # Récupérer la liste des jails actives
        jails_output = self.ssh_exec("sudo fail2ban-client status | grep 'Jail list' | sed 's/^.*Jail list://g'")
        jails = [jail.strip() for jail in jails_output.split(",") if jail.strip()]
        
        # Initialiser les compteurs
        total_banned = 0
        current_banned = 0
        banned_ips = []
        
        # Récupérer les stats pour chaque jail
        jail_stats = {}
        for jail in jails:
            jail_output = self.ssh_exec(f"sudo fail2ban-client status {jail}")
            
            # Extraire le nombre actuel de bannissements
            curr_banned_match = self.ssh_exec(f"echo '{jail_output}' | grep 'Currently banned:' | awk '{{print $NF}}'")
            curr_banned = int(curr_banned_match) if curr_banned_match.strip().isdigit() else 0
            
            # Extraire le nombre total de bannissements
            total_banned_match = self.ssh_exec(f"echo '{jail_output}' | grep 'Total banned:' | awk '{{print $NF}}'")
            tot_banned = int(total_banned_match) if total_banned_match.strip().isdigit() else 0
            
            # Récupérer la liste des IP bannies
            banned_list = self.ssh_exec(f"echo '{jail_output}' | grep 'Banned IP list:' | sed 's/^.*Banned IP list://g'")
            jail_banned_ips = [ip.strip() for ip in banned_list.split() if ip.strip()]
            
            jail_stats[jail] = {
                "current_banned": curr_banned,
                "total_banned": tot_banned,
                "banned_ips": jail_banned_ips
            }
            
            total_banned += tot_banned
            current_banned += curr_banned
            banned_ips.extend(jail_banned_ips)
        
        return {
            "active": True,
            "jails": jails,
            "total_banned": total_banned,
            "current_banned": current_banned,
            "banned_ips": banned_ips,
            "jail_stats": jail_stats
        }
    

    def was_ip_banned_by_fail2ban(self, ip: str):
        cmd = f"sudo grep 'Ban' /var/log/fail2ban.log | grep {ip}"
        output = self.ssh_exec(cmd)
        print()
        print(output)
        print()
        return ip in output




    #-------------------------------------------------------------------------------------
    #--------------------------------- CROWDSEC ------------------------------------------
    #-------------------------------------------------------------------------------------

    def enable_crowdsec_http_ratelimit(self, ban_time_seconds: int):
        cmds = [
            # Modifier le profil
            f"sudo sed -i 's/duration: .*/duration: {ban_time_seconds}s/' /etc/crowdsec/profiles.yaml",

            # Purger les anciennes décisions et alertes
            "sudo cscli decisions delete --all",
            "sudo cscli alerts delete --all",

            # Nettoyer les logs NGINX
            "sudo truncate -s 0 /var/log/nginx/access.log",
            "sudo truncate -s 0 /var/log/nginx/error.log",

            # Redémarrer CrowdSec
            "sudo systemctl restart crowdsec",

            # Relancer le bouncer pour qu’il reconfigure iptables
            "sudo systemctl restart crowdsec-firewall-bouncer"
        ]
        for cmd in cmds:
            self.ssh_exec(cmd)





    def disable_crowdsec(self):
        # Purge les décisions et redémarre CrowdSec sans modifier le profil.
        cmds = [
            "sudo cscli decisions delete --all",
            "sudo cscli alerts delete --all",
            "sudo systemctl restart crowdsec"
        ]
        for cmd in cmds:
            self.ssh_exec(cmd)




    def was_ip_banned_by_crowdsec(self, ip: str) -> bool:
        try:
            output = self.ssh_exec(f"sudo cscli alerts list -i {ip} -o raw")
            # Ex: chaque ligne contient ban:<n> si la décision existe
            return "ban:" in output
        except Exception as e:
            print(f"[!] Erreur dans was_ip_banned_by_crowdsec: {e}")
            return False



    #-------------------------------------------------------------------------------------
    #------------------------------ RATELIMIT NGINX --------------------------------------
    #-------------------------------------------------------------------------------------
    
    def enable_nginx_ratelimit(self):
        nginx_conf = """user www-data;
    worker_processes auto;
    pid /run/nginx.pid;
    error_log /var/log/nginx/error.log;
    include /etc/nginx/modules-enabled/*.conf;

    events {
        worker_connections 768;
    }

    http {
        limit_req_zone $binary_remote_addr zone=periplimit:10m rate=100r/s;

        sendfile on;
        tcp_nopush on;
        types_hash_max_size 2048;
        default_type application/octet-stream;

        include /etc/nginx/mime.types;

        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;

        gzip on;

        include /etc/nginx/conf.d/*.conf;
        include /etc/nginx/sites-enabled/*;
    }"""

        site_conf = """server {
        listen 80 default_server;
        listen [::]:80 default_server;

        location / {
            limit_req zone=periplimit burst=1 nodelay;
            proxy_pass http://127.0.0.1:8081;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
    }"""

        self.ssh_exec(f"echo '{nginx_conf}' | sudo tee /etc/nginx/nginx.conf > /dev/null")
        self.ssh_exec(f"echo '{site_conf}' | sudo tee /etc/nginx/sites-available/default > /dev/null")
        self.ssh_exec("sudo nginx -t && sudo systemctl reload nginx")
    
    
    def disable_nginx_ratelimit(self):
        default_nginx_conf = """user www-data;
    worker_processes auto;
    pid /run/nginx.pid;
    error_log /var/log/nginx/error.log;
    include /etc/nginx/modules-enabled/*.conf;

    events {
        worker_connections 768;
    }

    http {
        sendfile on;
        tcp_nopush on;
        types_hash_max_size 2048;
        default_type application/octet-stream;

        include /etc/nginx/mime.types;

        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;

        gzip on;

        include /etc/nginx/conf.d/*.conf;
        include /etc/nginx/sites-enabled/*;
    }"""

        default_site_conf = """server {
        listen 80 default_server;
        listen [::]:80 default_server;

        location / {
            proxy_pass http://127.0.0.1:8081;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
    }"""

        self.ssh_exec(f"echo '{default_nginx_conf}' | sudo tee /etc/nginx/nginx.conf > /dev/null")
        self.ssh_exec(f"echo '{default_site_conf}' | sudo tee /etc/nginx/sites-available/default > /dev/null")
        self.ssh_exec("sudo nginx -t && sudo systemctl reload nginx")
                
                
    def enable_iptables_recent_ratelimit(self, threshold=100, seconds=1, bantime=40):
        cmds = [
            # 1) Charger les modules noyau pour xt_recent, xt_set et ipset
            "sudo modprobe xt_set",
            "sudo modprobe xt_recent",
            "sudo modprobe ip_set",
            "sudo modprobe ip_set_hash_ip",

            # 2) (Re)créer proprement l'ipset "blacklist"
            "sudo ipset destroy blacklist 2>/dev/null || true",
            f"sudo ipset create blacklist hash:ip timeout {bantime}",

            # 3) Créer la chaîne dédiée + la lier à INPUT sur le port 80
            "sudo iptables -N HTTP_RATELIMIT_CHAIN 2>/dev/null || true",
            ("sudo iptables -C INPUT -p tcp --dport 80 -j HTTP_RATELIMIT_CHAIN 2>/dev/null "
            "|| sudo iptables -I INPUT -p tcp --dport 80 -j HTTP_RATELIMIT_CHAIN"),

            # 4) Vider la chaîne pour repartir propre
            "sudo iptables -F HTTP_RATELIMIT_CHAIN",

            # 5) Marquer chaque connexion HTTP dans recent
            "sudo iptables -A HTTP_RATELIMIT_CHAIN -p tcp --dport 80 "
            "-m recent --name HTTP_RATELIMIT --set --rsource",

            # 6) Si > threshold hits en < seconds → ajouter à l'ipset
            f"sudo iptables -A HTTP_RATELIMIT_CHAIN -p tcp --dport 80 "
            f"-m recent --name HTTP_RATELIMIT --update "
            f"--seconds {seconds} --hitcount {threshold} --rsource "
            "-j SET --add-set blacklist src",

            # 7) Log des requêtes bloquées (utile pour debug)
            "sudo iptables -A HTTP_RATELIMIT_CHAIN -m set --match-set blacklist src "
            "-j LOG --log-prefix 'HTTP_IPSET_DROP: '",

            # 8) Enfin DROP vraiment le HTTP
            "sudo iptables -A HTTP_RATELIMIT_CHAIN -m set --match-set blacklist src "
            "-j DROP",
        ]
        for cmd in cmds:
            self.ssh_exec(cmd)


    def disable_iptables_recent_ratelimit(self):
        cmds = [
            "sudo iptables -D INPUT -p tcp --dport 80 -j HTTP_RATELIMIT_CHAIN 2>/dev/null || true",
            "sudo iptables -F HTTP_RATELIMIT_CHAIN 2>/dev/null || true",
            "sudo iptables -X HTTP_RATELIMIT_CHAIN 2>/dev/null || true",
            "sudo ipset destroy blacklist 2>/dev/null || true",
        ]
        for cmd in cmds:
            self.ssh_exec(cmd)
            
            
    def force_disable_recent_ipset(self):
        cmds = [
            "sudo iptables -F",
            "sudo iptables -X",
            "sudo iptables -t raw -F",
            "sudo iptables -t raw -X",
            "sudo iptables -t nat -F",
            "sudo iptables -t nat -X",
            "sudo iptables -t mangle -F",
            "sudo iptables -t mangle -X",
            "sudo ipset destroy blacklist 2>/dev/null || true",
            "sudo ipset destroy crowdsec-blacklists 2>/dev/null || true",
            "sudo ipset destroy crowdsec-blacklists-0 2>/dev/null || true",
            "sudo ipset destroy crowdsec6-blacklists 2>/dev/null || true",
            "sudo modprobe -r xt_recent || true",
            "sudo modprobe -r xt_set || true",
            "sudo modprobe -r ip_set_hash_ip || true",
            "sudo modprobe -r ip_set || true"
        ]
        for cmd in cmds:
            self.ssh_exec(cmd)


    def is_ip_in_ipset(self, ip: str) -> bool:
        try:
            output = self.ssh_exec("sudo ipset list blacklist")
            return ip in output
        except Exception as e:
            print(f"[!] Erreur is_ip_in_ipset : {e}")
            return False


    def wait_until_http_restored(self, target_url, timeout_seconds=60, check_interval=5):
        print(f"[*] Attente du retour du service HTTP (timeout max {timeout_seconds}s)...")
        for elapsed in range(0, timeout_seconds, check_interval):
            try:
                r = requests.get(target_url, timeout=5, headers={"Connection": "close"})
                if r.status_code == 200:
                    print(f"[✓] Service restauré après {elapsed}s")
                    return
                else:
                    print(f"[{elapsed}s] HTTP {r.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"[{elapsed}s] Erreur : {e}")
            time.sleep(check_interval)
        raise TimeoutError("Service HTTP toujours inaccessible après le délai maximal")


    def restore_default_firewall_rules(self):
        print("[*] Restauration des règles iptables par défaut du setup...")

        iface = self.ssh_exec("ip route get 8.8.8.8 | awk '/dev/ {print $5}'").strip()

        cmds = [
            # 1. Créer la chaîne CROWDSEC_CHAIN si elle n'existe pas
            "sudo iptables -N CROWDSEC_CHAIN 2>/dev/null || true",

            # 2. Lier la chaîne CROWDSEC_CHAIN à INPUT (si pas déjà fait)
            ("sudo iptables -C INPUT -j CROWDSEC_CHAIN 2>/dev/null || "
            "sudo iptables -I INPUT -j CROWDSEC_CHAIN"),

            # 3. Règles classiques : loopback, ssh
            "sudo iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || sudo iptables -I INPUT -i lo -j ACCEPT",
            "sudo iptables -C INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || sudo iptables -I INPUT -p tcp --dport 22 -j ACCEPT",

            # 4. SYNPROXY
            (f"sudo iptables -C INPUT -i {iface} -p tcp --dport 80 -m state --state INVALID,UNTRACKED "
            f"-j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460 2>/dev/null || "
            f"sudo iptables -A INPUT -i {iface} -p tcp --dport 80 -m state --state INVALID,UNTRACKED "
            f"-j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460"),

            # 5. DROP invalid et autoriser established
            "sudo iptables -C INPUT -m state --state INVALID -j DROP 2>/dev/null || sudo iptables -A INPUT -m state --state INVALID -j DROP",
            "sudo iptables -C INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || sudo iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT",

            # 6. Autoriser HTTP (après SYNPROXY)
            "sudo iptables -C INPUT -p tcp --dport 80 -m state --state NEW -j ACCEPT 2>/dev/null || sudo iptables -A INPUT -p tcp --dport 80 -m state --state NEW -j ACCEPT",

            # 7. Bloquer accès direct à Apache depuis l'extérieur
            ("sudo iptables -C INPUT ! -s 127.0.0.1/32 -p tcp --dport 8081 -j DROP 2>/dev/null || "
            "sudo iptables -A INPUT ! -s 127.0.0.1/32 -p tcp --dport 8081 -j DROP"),

            # 8. Ajouter règle de DROP CrowdSec si ipset encore présent
            ("sudo iptables -C CROWDSEC_CHAIN -m set --match-set crowdsec-blacklists-0 src -j DROP 2>/dev/null || "
            "sudo iptables -A CROWDSEC_CHAIN -m set --match-set crowdsec-blacklists-0 src -j DROP"),
        ]

        for cmd in cmds:
            self.ssh_exec(cmd)

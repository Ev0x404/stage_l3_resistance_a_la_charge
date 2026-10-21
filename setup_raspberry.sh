#!/bin/bash

RPI_USER=raspberry
RPI_IP=192.168.1.40

echo "[+] Script d'installation complet amélioré (Apache + NGINX + SYNPROXY + FAIL2BAN)"
echo "[+] Connexion au Raspberry Pi $RPI_IP via SSH..."

# Une seule connexion SSH pour tout le script
ssh $RPI_USER@$RPI_IP << 'EOF'
  
  echo "[+] Configuration des réponses automatiques pour debconf..."
  echo 'mariadb-server-10.11 mysql-server/root_password password root' | sudo debconf-set-selections
  echo 'mariadb-server-10.11 mysql-server/root_password_again password root' | sudo debconf-set-selections
  echo 'mariadb-server-10.11 mysql-server/remove-data boolean true' | sudo debconf-set-selections
  
  #=====================================================================
  # ÉTAPE 1: NETTOYAGE COMPLET ET RÉPARATION DE L'INSTALLATION PRÉCÉDENTE
  #=====================================================================
  echo "[+] Nettoyage complet de l'installation précédente..."
  
  # Arrêt des services avec vérification
  echo "[*] Arrêt des services en cours d'exécution..."
  sudo systemctl stop apache2 2>/dev/null || true
  sudo systemctl stop nginx 2>/dev/null || true
  sudo systemctl stop mariadb 2>/dev/null || true
  sudo systemctl stop fail2ban 2>/dev/null || true
  
  # Force kill des processus qui pourraient persister
  echo "[*] Force kill des processus résiduels..."
  sudo killall -9 apache2 2>/dev/null || true
  sudo killall -9 nginx 2>/dev/null || true
  sudo killall -9 mysqld 2>/dev/null || true
  
  # Réparation des paquets cassés
  echo "[*] Réparation des paquets cassés..."
  sudo dpkg --configure -a || true
  sudo apt-get install -f -y || true
  
  # Suppression des paquets avec purge plus agressive
  echo "[*] Suppression des paquets..."
  DEBIAN_FRONTEND=noninteractive sudo apt-get remove --purge -y apache2 apache2-bin apache2-data apache2-utils nginx nginx-common mariadb-server mariadb-client mariadb-common fail2ban 2>/dev/null || true
  
  # Second nettoyage pour les dépendances
  echo "[*] Nettoyage des dépendances..."
  DEBIAN_FRONTEND=noninteractive sudo apt-get autoremove --purge -y
  
  # Suppression manuelle des répertoires de configuration
  echo "[*] Suppression des fichiers de configuration restants..."
  sudo rm -rf /etc/apache2 /etc/nginx /etc/mysql /var/lib/mysql /var/www/html/index.html /etc/fail2ban 2>/dev/null || true
  
  # Nettoyage des fichiers logs de Fail2Ban et débannissement de toutes les IP
  echo "[*] Nettoyage des logs et bannissements Fail2Ban..."
  # Supprimer ou vider les logs
  sudo rm -f /var/log/fail2ban.log* 2>/dev/null || true
  sudo truncate -s 0 /var/log/fail2ban.log 2>/dev/null || true
  
  # Si fail2ban est encore actif, débannir toutes les IP
  if systemctl is-active --quiet fail2ban; then
    echo "[*] Débannissement de toutes les IP avant arrêt..."
    sudo fail2ban-client unban --all 2>/dev/null || true
  fi
  
  # Suppression des fichiers de socket et de service
  sudo rm -f /var/run/apache2/* /var/run/nginx/* /var/run/mysqld/* 2>/dev/null || true
  
  # Nettoyage des règles iptables
  echo "[*] Nettoyage des règles iptables..."
  # Supprimer spécifiquement les chaînes fail2ban avant le nettoyage général
  sudo iptables -D INPUT -j f2b-nginx-too-many-requests 2>/dev/null || true
  sudo iptables -F f2b-nginx-too-many-requests 2>/dev/null || true
  sudo iptables -X f2b-nginx-too-many-requests 2>/dev/null || true
  
  # Puis nettoyage général des règles
  sudo iptables -F
  sudo iptables -X
  sudo iptables -t nat -F
  sudo iptables -t nat -X
  sudo iptables -t mangle -F
  sudo iptables -t mangle -X
  sudo iptables -t raw -F
  sudo iptables -t raw -X
  sudo iptables -P INPUT ACCEPT
  sudo iptables -P FORWARD ACCEPT
  sudo iptables -P OUTPUT ACCEPT
  
  # Nettoyage du cache apt
  echo "[*] Nettoyage du cache apt..."
  sudo apt-get clean
  
  #=====================================================================
  # ÉTAPE 2: INSTALLATION DES PAQUETS NÉCESSAIRES AVEC VÉRIFICATION
  #=====================================================================
  echo "[+] Mise à jour du système et installation des paquets..."
  
  # Mise à jour du système
  DEBIAN_FRONTEND=noninteractive sudo apt-get update
  
  # Installation d'Apache2 avec vérification
  echo "[*] Installation d'Apache2..."
  DEBIAN_FRONTEND=noninteractive sudo apt-get install -y apache2
  if [ $? -ne 0 ]; then
    echo "[!] Installation d'Apache2 échouée, tentative de correction..."
    sudo apt-get install -f -y
    DEBIAN_FRONTEND=noninteractive sudo apt-get install -y apache2
  fi
  
  # Vérification que Apache a été installé correctement
  if ! dpkg -l | grep -q apache2; then
    echo "[!] Erreur critique: Apache2 n'a pas pu être installé!"
    exit 1
  fi
  
  # Installation de Nginx avec vérification
  echo "[*] Installation de Nginx..."
  DEBIAN_FRONTEND=noninteractive sudo apt-get install -y nginx
  if [ $? -ne 0 ]; then
    echo "[!] Installation de Nginx échouée, tentative de correction..."
    sudo apt-get install -f -y
    DEBIAN_FRONTEND=noninteractive sudo apt-get install -y nginx
  fi
  
  # Vérification que Nginx a été installé correctement
  if ! dpkg -l | grep -q nginx; then
    echo "[!] Erreur critique: Nginx n'a pas pu être installé!"
    exit 1
  fi
  
  # Installation de PHP avec vérification
  echo "[*] Installation de PHP..."
  DEBIAN_FRONTEND=noninteractive sudo apt-get install -y php libapache2-mod-php
  if [ $? -ne 0 ]; then
    echo "[!] Installation de PHP échouée, tentative de correction..."
    sudo apt-get install -f -y
    DEBIAN_FRONTEND=noninteractive sudo apt-get install -y php libapache2-mod-php
  fi
  
  # Vérification que PHP a été installé correctement
  if ! dpkg -l | grep -q php; then
    echo "[!] Erreur critique: PHP n'a pas pu être installé!"
    exit 1
  fi
  
  # Installation de Fail2ban avec vérification
  echo "[*] Installation de Fail2ban..."
  DEBIAN_FRONTEND=noninteractive sudo apt-get install -y fail2ban
  if [ $? -ne 0 ]; then
    echo "[!] Installation de Fail2ban échouée, tentative de correction..."
    sudo apt-get install -f -y
    DEBIAN_FRONTEND=noninteractive sudo apt-get install -y fail2ban
  fi
  
  # Vérification que Fail2ban a été installé correctement
  if ! dpkg -l | grep -q fail2ban; then
    echo "[!] Erreur critique: Fail2ban n'a pas pu être installé!"
    exit 1
  fi
  
  # Vérification et création manuelle du fichier de configuration Nginx si nécessaire
  if [ ! -f /etc/nginx/nginx.conf ]; then
    echo "[!] Fichier de configuration nginx.conf manquant, création manuelle..."
    sudo mkdir -p /etc/nginx
    sudo tee /etc/nginx/nginx.conf > /dev/null << 'NGINXMAIN'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
        worker_connections 768;
        # multi_accept on;
}

http {
        sendfile on;
        tcp_nopush on;
        tcp_nodelay on;
        keepalive_timeout 65;
        types_hash_max_size 2048;

        include /etc/nginx/mime.types;
        default_type application/octet-stream;

        ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; # Dropping SSLv3, ref: POODLE
        ssl_prefer_server_ciphers on;

        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;

        gzip on;

        include /etc/nginx/conf.d/*.conf;
        include /etc/nginx/sites-enabled/*;
}
NGINXMAIN
  fi
  
  # Création des répertoires nécessaires pour Nginx
  echo "[*] Création des répertoires nécessaires pour Nginx..."
  sudo mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled /var/log/nginx
  sudo chown -R www-data:www-data /var/log/nginx
  
  # Installation des autres paquets
  echo "[*] Installation des autres paquets..."
  DEBIAN_FRONTEND=noninteractive sudo apt-get install -y net-tools iproute2 tcpdump python3 python3-pip iptables conntrack
  
  # Chargement des modules kernel nécessaires
  echo "[*] Chargement des modules kernel nécessaires..."
  sudo modprobe nf_synproxy_core || true
  sudo modprobe nf_conntrack || true
  
  #=====================================================================
  # ÉTAPE 3: CONFIGURATION D'APACHE (PORT 8081)
  #=====================================================================
  echo "[+] Configuration d'Apache sur le port 8081..."
  
  # Configuration du port 8081 pour Apache (modifié de 8080)
  sudo tee /etc/apache2/ports.conf > /dev/null << 'PORTSCONF'
# If you just change the port or add more ports here, you will likely also
# have to change the VirtualHost statement in
# /etc/apache2/sites-enabled/000-default.conf

Listen 8081

<IfModule ssl_module>
	Listen 443
</IfModule>

<IfModule mod_gnutls.c>
	Listen 443
</IfModule>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
PORTSCONF
  
  # Configuration du VirtualHost Apache
  sudo tee /etc/apache2/sites-available/000-default.conf > /dev/null << 'VHOSTCONF'
<VirtualHost *:8081>
	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/html

	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
VHOSTCONF

  # Création d'une page d'index PHP par défaut
  sudo mkdir -p /var/www/html
  echo "<?php \$start = microtime(true); while (microtime(true) - \$start < 3) {} echo 'OK'; ?>" | sudo tee /var/www/html/index.php > /dev/null
  echo "<html><body><h1>Apache est en fonctionnement sur le port 8081</h1><p>Cette page est servie par Apache, accessible via le reverse proxy Nginx.</p></body></html>" | sudo tee /var/www/html/index.html > /dev/null
  
  # S'assurer que les fichiers sont accessibles
  sudo chown -R www-data:www-data /var/www/html
  sudo chmod -R 755 /var/www/html
  
  # Désactiver puis réactiver le site par défaut
  sudo a2dissite 000-default || true
  sudo a2ensite 000-default || true
  
  # Configuration du module prefork MPM
  echo "[*] Configuration du module prefork MPM..."
  sudo tee /etc/apache2/mods-available/mpm_prefork.conf > /dev/null << 'PREFORKMPM'
<IfModule mpm_prefork_module>
    # StartServers: number of server processes to start
    # MinSpareServers: minimum number of server processes which are kept spare
    # MaxSpareServers: maximum number of server processes which are kept spare
    # MaxRequestWorkers: maximum number of server processes allowed to start
    # MaxConnectionsPerChild: maximum number of requests a server process serves
    StartServers		125
    MinSpareServers		120
    MaxSpareServers		150
    MaxRequestWorkers	150
    MaxConnectionsPerChild	0
</IfModule>
PREFORKMPM
  
  # Activer le module prefork MPM
  sudo a2enmod mpm_prefork || true
  
  # Vérification et redémarrage d'Apache
  echo "[*] Vérification de la configuration Apache..."
  sudo apache2ctl configtest || true
  
  echo "[*] Redémarrage d'Apache..."
  sudo systemctl restart apache2 || true
  
  # Si Apache n'a pas démarré, on force le start
  if ! sudo systemctl is-active apache2 > /dev/null; then
    echo "[!] Apache n'a pas démarré correctement. Tentative de démarrage forcé..."
    sudo systemctl start apache2 || true
    sleep 2
  fi
  
  #=====================================================================
  # ÉTAPE 4: CONFIGURATION DE NGINX (PORT 80)
  #=====================================================================
  echo "[+] Configuration de NGINX comme reverse proxy vers Apache..."
  
  # Configuration de NGINX
  sudo mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled
  sudo tee /etc/nginx/sites-available/default > /dev/null << 'NGINXCONF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    location / {
        proxy_pass http://127.0.0.1:8081;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
NGINXCONF
  
  # Créer le lien symbolique si nécessaire
  if [ ! -L /etc/nginx/sites-enabled/default ]; then
    sudo ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default
  fi
  
  # Vérification et redémarrage de NGINX
  echo "[*] Vérification de la configuration NGINX..."
  sudo nginx -t || true
  
  echo "[*] Redémarrage de NGINX..."
  sudo systemctl restart nginx || true
  
  # Si NGINX n'a pas démarré, on force le start
  if ! sudo systemctl is-active nginx > /dev/null; then
    echo "[!] NGINX n'a pas démarré correctement. Tentative de démarrage forcé..."
    sudo systemctl start nginx || true
    sleep 2
  fi
  
  #=====================================================================
  # ÉTAPE 5: CONFIGURATION DE SYNPROXY
  #=====================================================================
  echo "[+] Configuration de SYNPROXY suivant les étapes officielles..."
  
  # Détection de l'interface réseau
  DEV=$(ip route get 8.8.8.8 | awk '/dev/ {print $5}')
  PORT=80
  
  echo "[*] Interface détectée: $DEV, Port à protéger: $PORT"
  
  # Étape 1: Empêcher la création d'entrées conntrack pour les paquets SYN
  echo "[*] Étape 1: Empêcher la création d'entrées conntrack pour les paquets SYN..."
  sudo iptables -t raw -I PREROUTING -i $DEV -p tcp -m tcp --syn --dport $PORT -j CT --notrack
  
  # Étape 2: Activer un suivi de connexion plus strict
  echo "[*] Étape 2: Activer un suivi de connexion plus strict..."
  sudo sysctl -w net.netfilter.nf_conntrack_tcp_loose=0
  
  # Étape 3: Configurer la cible SYNPROXY
  echo "[*] Étape 3: Configurer la cible SYNPROXY..."
  sudo iptables -A INPUT -i $DEV -p tcp -m tcp --dport $PORT -m state --state INVALID,UNTRACKED \
    -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
  
  # Étape 4: Supprimer les paquets à l'état INVALID
  echo "[*] Étape 4: Supprimer les paquets à l'état INVALID..."
  sudo iptables -A INPUT -m state --state INVALID -j DROP
  
  # Étape 5: Activer les horodatages TCP
  echo "[*] Étape 5: Activer les horodatages TCP..."
  sudo sysctl -w net.ipv4.tcp_timestamps=1
  
  # Étape 6: Optimisation des paramètres conntrack
  echo "[*] Étape 6: Optimisation des paramètres conntrack..."
  if [ -f /sys/module/nf_conntrack/parameters/hashsize ]; then
    sudo bash -c 'echo 131072 > /sys/module/nf_conntrack/parameters/hashsize'
  else
    echo "[!] Le paramètre hashsize n'est pas directement accessible, utilisation de sysctl..."
  fi
  
  # Augmenter le nombre maximal de connexions suivies
  sudo sysctl -w net.netfilter.nf_conntrack_max=262144
  
  # Règles supplémentaires pour assurer le fonctionnement
  echo "[*] Ajout de règles supplémentaires..."
  
  # Autoriser SSH et localhost
  sudo iptables -I INPUT 1 -p tcp --dport 22 -j ACCEPT
  sudo iptables -I INPUT 1 -i lo -j ACCEPT
  
  # Autoriser les connexions établies
  sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  sudo iptables -A INPUT -p tcp --dport $PORT -m state --state NEW -j ACCEPT
  
  # Bloquer l'accès direct au port 8081 sauf depuis localhost
  echo "[*] Blocage du port 8081 depuis l'extérieur..."
  sudo iptables -A INPUT -p tcp --dport 8081 ! -s 127.0.0.1 -j DROP

  #=====================================================================
  # ÉTAPE 6: CONFIGURATION DE FAIL2BAN
  #=====================================================================
  echo "[+] Configuration de Fail2Ban pour bloquer les requêtes HTTP excessives..."
  
  # 6.1. Désactiver la jail sshd pour éviter les problèmes
  echo "[*] Désactivation de la jail SSH par défaut..."
  sudo mkdir -p /etc/fail2ban
  sudo tee /etc/fail2ban/jail.local > /dev/null << 'JAILLOCAL'
[sshd]
enabled = false
JAILLOCAL

  # 6.2. Créer la jail personnalisée pour nginx-too-many-requests
  echo "[*] Création de la jail nginx-too-many-requests..."
  sudo mkdir -p /etc/fail2ban/jail.d
  sudo tee /etc/fail2ban/jail.d/nginx-too-many-requests.local > /dev/null << 'JAILNGINX'
[nginx-too-many-requests]
enabled = true
filter = nginx-too-many-requests
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 100
findtime = 60
bantime = 30
action = iptables[name=HTTP, port=http, protocol=tcp]
JAILNGINX

  # 6.3. Créer le filtre personnalisé
  echo "[*] Création du filtre pour détecter les requêtes HTTP excessives..."
  sudo mkdir -p /etc/fail2ban/filter.d
  sudo tee /etc/fail2ban/filter.d/nginx-too-many-requests.conf > /dev/null << 'FILTERNGINX'
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*
FILTERNGINX

  # 6.4. S'assurer que tous les répertoires de logs existent
  sudo mkdir -p /var/log/fail2ban
  sudo touch /var/log/fail2ban.log
  sudo chmod 644 /var/log/fail2ban.log
  
  # 6.5. Redémarrage de Fail2Ban
  echo "[*] Redémarrage de Fail2Ban..."
  sudo systemctl restart fail2ban
  
  # 6.6. Vérification que Fail2Ban est bien lancé
  sleep 3
  if ! sudo systemctl is-active fail2ban > /dev/null; then
    echo "[!] Fail2Ban n'a pas démarré correctement. Tentative de démarrage forcé..."
    sudo systemctl start fail2ban || true
    sleep 2
  fi
  
  # 6.7. Vérification des jails actives
  echo "[*] Jails Fail2Ban activées:"
  sudo fail2ban-client status
  
  # 6.8. Vérification spécifique de la jail nginx-too-many-requests
  echo "[*] Statut de la jail nginx-too-many-requests:"
  sudo fail2ban-client status nginx-too-many-requests || echo "[!] La jail nginx-too-many-requests n'est pas encore active"

  #=====================================================================
  # ÉTAPE 7: VÉRIFICATION DE L'INSTALLATION COMPLÈTE
  #=====================================================================
  echo "[+] Vérification de l'installation..."
  
  # Vérification des services
  echo "[*] Statut des services:"
  sudo systemctl status apache2 --no-pager | grep Active || echo "Apache: non démarré"
  sudo systemctl status nginx --no-pager | grep Active || echo "Nginx: non démarré"
  sudo systemctl status fail2ban --no-pager | grep Active || echo "Fail2Ban: non démarré"
  
  # Vérification des ports en écoute
  echo "[*] Ports en écoute:"
  sudo netstat -tulpn | grep -E ':(80|8081)' || echo "[!] Aucun service détecté sur les ports 80/8081"
  
  # Test de connexion locale
  echo "[*] Test de connexion locale (HTTP)..."
  curl -s -I http://localhost || echo "[!] La connexion locale a échoué"
  
  # Test de l'accès à index.php
  echo "[*] Test d'accès à index.php..."
  curl -s http://localhost/index.php || echo "[!] L'accès à index.php a échoué"
  
  # Affichage des statistiques SYNPROXY
  echo "[*] Statistiques SYNPROXY:"
  cat /proc/net/stat/synproxy 2>/dev/null || echo "[!] Statistiques SYNPROXY non disponibles"
  
  # Affichage des règles iptables
  echo "[*] Règles iptables:"
  sudo iptables -L -v | head -n 20
  
  echo "[✓] Installation et configuration terminées !"
  echo "[✓] Apache écoute sur le port 8081 et sert index.php"
  echo "[✓] NGINX écoute sur le port 80 et agit comme reverse proxy vers Apache"
  echo "[✓] SYNPROXY est configuré pour protéger le port 80"
  echo "[✓] Fail2Ban est configuré pour bloquer les IP qui font trop de requêtes HTTP"


  #=====================================================================
  # ÉTAPE 8: INSTALLATION CROWDSEC
  #=====================================================================

  echo "[1/10] Mise à jour du système..."
  sudo apt update

  echo "[2/10] Installation des dépendances..."
  sudo apt install -y curl gnupg lsb-release

  echo "[3/10] Ajout du dépôt officiel CrowdSec..."
  curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | sudo bash

  echo "[4/10] Installation de CrowdSec..."
  sudo apt install -y crowdsec

  echo "[5/10] Configuration de la confidentialité..."
  sudo sed -i 's/send_metrics: true/send_metrics: false/' /etc/crowdsec/config.yaml
  sudo sed -i 's/share_decisions: true/share_decisions: false/' /etc/crowdsec/config.yaml

  echo "[6/10] Installation des postoverflows..."
  sudo cscli postoverflows install crowdsecurity/rdns
  sudo cscli postoverflows install crowdsecurity/fix-logs

  echo "[+] Patch du parser geoip-enrich pour corriger la syntaxe (brackets)..."
sudo tee /etc/crowdsec/parsers/s02-enrich/geoip-enrich.yaml > /dev/null <<'EOC'
filter: |
  let ipv6Check = IsIPV6(evt.Meta.source_ip);
  "source_ip" in evt.Meta && (
    (!ipv6Check) ||
    (ipv6Check &&
      not (IpInRange(evt.Meta.source_ip, "::1/128") ||
           IpInRange(evt.Meta.source_ip, "fd00::/8") ||
           IpInRange(evt.Meta.source_ip, "fc00::/7"))
    )
  )

name: crowdsecurity/geoip-enrich
description: "Populate event with geoloc info : as, country, coords, source range."
data:
  - source_url: https://hub-data.crowdsec.net/mmdb_update/GeoLite2-City.mmdb
    dest_file: GeoLite2-City.mmdb
  - source_url: https://hub-data.crowdsec.net/mmdb_update/GeoLite2-ASN.mmdb
    dest_file: GeoLite2-ASN.mmdb
statics:
  - method: GeoIpCity
    expression: evt.Meta.source_ip
  - meta: IsoCode
    expression: evt.Enriched.IsoCode
  - meta: IsInEU
    expression: evt.Enriched.IsInEU
  - meta: GeoCoords
    expression: evt.Enriched.GeoCoords
  - method: GeoIpASN
    expression: evt.Meta.source_ip
  - meta: ASNNumber
    expression: evt.Enriched.ASNNumber
  - meta: ASNOrg
    expression: evt.Enriched.ASNOrg
  - method: IpToRange
    expression: evt.Meta.source_ip
  - meta: SourceRange
    expression: evt.Enriched.SourceRange
EOC

  sudo systemctl reload crowdsec

  echo "[7/10] Création du scénario custom-http-ratelimit..."
  sudo tee /etc/crowdsec/scenarios/custom-http-ratelimit.yaml > /dev/null <<'EOC'
name: custom/http-ratelimit
description: "Too many HTTP requests per IP in a short time"
type: leaky
filter: |
  evt.Meta.log_type == 'http_access-log' &&
  evt.Parsed.verb == 'GET' &&
  evt.Parsed.status in ["200", "400", "408", "431"]
groupby: evt.Meta.source_ip
capacity: 100
leakspeed: 10ms
blackhole: 1s
labels:
  service: http
  type: ratelimit
  remediation: true
EOC

  echo "[8/10] Configuration des logs NGINX..."
  sudo tee /etc/crowdsec/acquis.yaml > /dev/null <<'EOC'
filenames:
  - /var/log/nginx/access.log
  - /var/log/nginx/error.log
labels:
  type: nginx
mode: tail
EOC

  echo "[9/10] Suppression de la whitelist locale sur 192.168.0.0/16..."
  sudo sed -i '/192.168.0.0/d' /etc/crowdsec/parsers/s02-enrich/whitelists.yaml || true
  sudo sed -i '/192.168.0.0/d' /etc/crowdsec/hub/parsers/s02-enrich/crowdsecurity/whitelists.yaml || true
  sudo sed -i '/192.168.0.0/d' /etc/crowdsec/hub/parsers/s02-enrich/crowdsecurity/geoip-enrich.yaml || true

  echo "[10/10] Configuration du profil de bannissement (30s)..."
  sudo tee /etc/crowdsec/profiles.yaml > /dev/null <<'EOC'
name: custom-http-ratelimit
filters:
  - "Alert.Scenario == 'custom/http-ratelimit'"
decisions:
  - type: ban
    duration: 30s
on_success: break
---
name: default_ip_remediation
filters:
 - Alert.Remediation == true && Alert.GetScope() == "Ip"
decisions:
 - type: ban
   duration: 30s
on_success: break
---
name: default_range_remediation
filters:
 - Alert.Remediation == true && Alert.GetScope() == "Range"
decisions:
 - type: ban
   duration: 30s
on_success: break
EOC

  echo "[+] Installation du bouncer iptables..."
  sudo apt install -y crowdsec-firewall-bouncer-iptables

  echo "[✓] Redémarrage des services..."
  sudo systemctl restart crowdsec
  sudo systemctl restart crowdsec-firewall-bouncer

  echo "[✔] Installation CrowdSec terminée avec succès sur le Raspberry Pi !"
EOF

echo ""
echo "[+] Script terminé. Pour tester l'installation:"
echo "    curl -I http://${RPI_IP}"
echo "    curl http://${RPI_IP}/index.php"
echo ""
echo "[+] Pour tester une attaque SYN flood avec la protection SYNPROXY:"
echo "    python syn_flood.py ${RPI_IP} 80"
echo ""
echo "[+] Pour tester le bannissement par Fail2Ban:"
echo "    python3 test_fail2ban.py"
echo ""
echo "[+] Ce script peut être exécuté plusieurs fois sans problème."
echo "    Il effectuera un nettoyage complet à chaque exécution."
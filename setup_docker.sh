#!/bin/bash

echo -e "\n=============================="
echo "[+] ÉTAPE 1 : Apache + PHP sur port 8081"
echo "=============================="

# Nettoyage Apache + PHP
sudo systemctl stop apache2 2>/dev/null || true
sudo killall -9 apache2 2>/dev/null || true
sudo apt-get remove --purge -y apache2 apache2-bin apache2-data apache2-utils php libapache2-mod-php 2>/dev/null || true
sudo apt-get autoremove --purge -y
sudo apt-get clean
sudo rm -rf /etc/apache2 /var/www/html /var/log/apache2

# Installation Apache + PHP
sudo apt-get update
sudo apt-get install -y apache2 php libapache2-mod-php

# Fichiers de logs
sudo mkdir -p /var/log/apache2
sudo touch /var/log/apache2/access.log /var/log/apache2/error.log
sudo chown -R www-data:www-data /var/log/apache2

# Configuration port 8081
sudo tee /etc/apache2/ports.conf > /dev/null <<EOF
Listen 8081
<IfModule ssl_module>
	Listen 443
</IfModule>
<IfModule mod_gnutls.c>
	Listen 443
</IfModule>
EOF

sudo tee /etc/apache2/sites-available/000-default.conf > /dev/null <<EOF
<VirtualHost *:8081>
	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/html

	ErrorLog \${APACHE_LOG_DIR}/error.log
	CustomLog \${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
EOF

# Contenu HTML
sudo mkdir -p /var/www/html
echo "<?php \$start = microtime(true); while (microtime(true) - \$start < 3) {} echo 'OK'; ?>" | sudo tee /var/www/html/index.php > /dev/null
echo "<html><body><h1>Apache est en fonctionnement sur le port 8081</h1><p>Servi via NGINX.</p></body></html>" | sudo tee /var/www/html/index.html > /dev/null
sudo chown -R www-data:www-data /var/www/html
sudo chmod -R 755 /var/www/html
echo "ServerName localhost" | sudo tee -a /etc/apache2/apache2.conf


echo "[*] Configuration du module prefork MPM..."
sudo tee /etc/apache2/mods-available/mpm_prefork.conf > /dev/null << 'EOF'
<IfModule mpm_prefork_module>
    StartServers            125
    MinSpareServers         120
    MaxSpareServers         150
    MaxRequestWorkers       150
    MaxConnectionsPerChild  0
</IfModule>
EOF

# Désactiver les autres MPM et forcer prefork
sudo a2dismod mpm_event mpm_worker || true
sudo a2enmod mpm_prefork

# Vérification du MPM actif
echo "[*] MPM Apache actif :"
sudo apachectl -V | grep -i mpm

# Redémarrage complet
sudo apachectl stop || true
sleep 2
sudo apachectl start
echo "[✔] Apache lancé sur le port 8081"



echo -e "\n=============================="
echo "[+] ÉTAPE 2 : NGINX reverse proxy sur port 80"
echo "=============================="

# Install NGINX si nécessaire
sudo apt-get install -y nginx

sudo mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled

sudo tee /etc/nginx/sites-available/default > /dev/null << 'EOF'
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
EOF

sudo ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default

# Vérification et démarrage
if sudo nginx -t; then
    echo "[✔] Configuration NGINX OK"
    sudo nginx -s reload || sudo nginx
else
    echo "[❌] Erreur de configuration NGINX"
    exit 1
fi

echo "[✔] NGINX fonctionne sur le port 80"

echo -e "\n=============================="
echo "[+] ÉTAPE 3 : Fail2Ban protection HTTP"
echo "=============================="

# Install Fail2Ban
sudo apt-get install -y fail2ban

# jail SSH désactivée
sudo mkdir -p /etc/fail2ban
sudo tee /etc/fail2ban/jail.local > /dev/null << 'EOF'
[sshd]
enabled = false
EOF

# jail custom nginx-too-many-requests
sudo mkdir -p /etc/fail2ban/jail.d
sudo tee /etc/fail2ban/jail.d/nginx-too-many-requests.local > /dev/null << 'EOF'
[nginx-too-many-requests]
enabled = true
filter = nginx-too-many-requests
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 100
findtime = 60
bantime = 30
action = iptables[name=HTTP, port=http, protocol=tcp]
EOF

# filtre associé
sudo mkdir -p /etc/fail2ban/filter.d
sudo tee /etc/fail2ban/filter.d/nginx-too-many-requests.conf > /dev/null << 'EOF'
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*
EOF

# Préparation logs
sudo mkdir -p /var/log/fail2ban
sudo touch /var/log/fail2ban.log
sudo chmod 644 /var/log/fail2ban.log

# Démarrage Fail2Ban à la main
sudo pkill -f fail2ban-server || true
sudo fail2ban-client -x start
sleep 2

if pgrep fail2ban-server > /dev/null; then
    echo "[✔] Fail2Ban fonctionne"
else
    echo "[❌] Échec du démarrage de Fail2Ban"
    exit 1
fi

echo "[*] Jails actives :"
sudo fail2ban-client status || echo "[!] Impossible de récupérer le statut global"
sudo fail2ban-client status nginx-too-many-requests || echo "[!] Jail pas encore déclenchée"



echo -e "\n=============================="
echo "[+] ÉTAPE 4 : Installation et configuration de CrowdSec (avec pauses simulant l'exécution manuelle)"
echo "=============================="

echo "[1/10] Mise à jour du système..."
apt update

echo "[2/10] Installation des dépendances..."
apt install -y curl gnupg lsb-release

echo "[3/10] Ajout du dépôt officiel CrowdSec..."
curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash

echo "[4/10] Installation de CrowdSec..."
apt install -y crowdsec
sleep 2

echo "[5/10] Configuration de la confidentialité..."
sed -i 's/send_metrics: true/send_metrics: false/' /etc/crowdsec/config.yaml
sed -i 's/share_decisions: true/share_decisions: false/' /etc/crowdsec/config.yaml

echo "[6/10] Installation des postoverflows crowdsecurity/rdns et fix-logs..."
cscli postoverflows install crowdsecurity/rdns
cscli postoverflows install crowdsecurity/fix-logs

sudo tee /etc/crowdsec/parsers/s02-enrich/geoip-enrich.yaml > /dev/null <<'EOF'
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
EOF


echo "[7/10] Création du scénario custom-http-ratelimit (version correcte avec evt.Parsed)..."
tee /etc/crowdsec/scenarios/custom-http-ratelimit.yaml > /dev/null <<'EOC'
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
blackhole: 10s
labels:
  service: http
  type: ratelimit
  remediation: true
EOC

echo "[8/10] Configuration de l'acquisition des logs NGINX..."
tee /etc/crowdsec/acquis.yaml > /dev/null <<'EOC'
filenames:
  - /var/log/nginx/access.log
  - /var/log/nginx/error.log
labels:
  type: nginx
mode: tail
EOC

echo "[9/10] Suppression des whitelists IP privées..."
sed -i '/192.168.0.0/d' /etc/crowdsec/parsers/s02-enrich/whitelists.yaml || true
sed -i '/172.16.0.0/d' /etc/crowdsec/parsers/s02-enrich/whitelists.yaml || true
sed -i '/172.17.0.0/d' /etc/crowdsec/parsers/s02-enrich/whitelists.yaml || true
sed -i '/172.18.0.0/d' /etc/crowdsec/parsers/s02-enrich/whitelists.yaml || true
sed -i '/172.19.0.0/d' /etc/crowdsec/parsers/s02-enrich/whitelists.yaml || true
sed -i '/172.20.0.0/d' /etc/crowdsec/parsers/s02-enrich/whitelists.yaml || true
sed -i '/10.0.0.0/d'    /etc/crowdsec/parsers/s02-enrich/whitelists.yaml || true
sed -i '/192.168.0.0/d' /etc/crowdsec/hub/parsers/s02-enrich/crowdsecurity/whitelists.yaml || true
sed -i '/192.168.0.0/d' /etc/crowdsec/hub/parsers/s02-enrich/crowdsecurity/geoip-enrich.yaml || true

echo "[10/10] Configuration du profil de bannissement..."
tee /etc/crowdsec/profiles.yaml > /dev/null <<'EOC'
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

echo "[✓] Installation du bouncer iptables..."
apt install -y crowdsec-firewall-bouncer-iptables
sleep2

echo "[✓] Démarrage CrowdSec & bouncer sans systemd..."
pkill -f crowdsec || true
nohup /usr/bin/crowdsec -c /etc/crowdsec/config.yaml > /var/log/crowdsec.log 2>&1 &

pkill -f crowdsec-firewall-bouncer || true
nohup /usr/bin/crowdsec-firewall-bouncer -c /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml > /var/log/bouncer.log 2>&1 &

sleep 5

echo "[*] Attente que CrowdSec soit prêt (API active + scénario chargé)..."
for i in {1..15}; do
    if cscli metrics | grep custom/http-ratelimit | grep -q "Instantiated"; then
        echo "[✔] Scenario custom/http-ratelimit actif et CrowdSec prêt"
        break
    fi
    echo "[...] Tentative $i/15 : CrowdSec pas encore prêt"
    sleep 2
done

echo "[✔] Installation CrowdSec terminée et prête (mode sans systemd et API vérifiée)"

echo -e "\n✅ SETUP TERMINÉ : Apache + NGINX + Fail2Ban + CrowdSec prêts dans le conteneur."

# Garde le conteneur actif
tail -f /dev/null

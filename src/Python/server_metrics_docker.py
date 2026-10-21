import subprocess
import time
import socket
import requests


def get_local_ipv4():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


def was_ip_banned_by_fail2ban(ip):
    try:
        output = subprocess.check_output(["docker", "exec", "lamp-server", "grep", "Ban", "/var/log/fail2ban.log"], text=True)
        return ip in output
    except subprocess.CalledProcessError as e:
        print(f"[!] Erreur lors de la lecture des logs Fail2Ban : {e}")
        return False


def apply_fail2ban_bantime(bantime):
    try:
        jail_file = "/etc/fail2ban/jail.d/nginx-too-many-requests.local"
        subprocess.run([
            "docker", "exec", "-u", "root", "lamp-server",
            "sed", "-i", f"s/^bantime *=.*/bantime = {bantime}/", jail_file
        ], check=True)
        subprocess.run([
            "docker", "exec", "-u", "root", "lamp-server",
            "fail2ban-client", "reload"
        ], check=True)
        print(f"[+] Fail2Ban bantime mis à jour à {bantime}s et service opérationnel")
    except subprocess.CalledProcessError as e:
        print(f"[!] Erreur dans apply_fail2ban_bantime : {e}")


def disable_crowdsec():
    print("[*] Désactivation temporaire de CrowdSec...")
    subprocess.run(["docker", "exec", "-u", "root", "lamp-server", "pkill", "-f", "crowdsec"], check=False)
    subprocess.run(["docker", "exec", "-u", "root", "lamp-server", "pkill", "-f", "crowdsec-firewall-bouncer"], check=False)
    time.sleep(2)


def enable_crowdsec():
    print("[*] Réactivation propre de CrowdSec...")

    # Kill propre
    subprocess.run(["docker", "exec", "-u", "root", "lamp-server", "pkill", "-f", "crowdsec"], check=False)
    subprocess.run(["docker", "exec", "-u", "root", "lamp-server", "pkill", "-f", "crowdsec-firewall-bouncer"], check=False)
    time.sleep(2)

    # Lancement en tâche de fond explicitement via bash -c
    try:
        subprocess.run([
            "docker", "exec", "-u", "root", "lamp-server",
            "bash", "-c",
            "nohup crowdsec -c /etc/crowdsec/config.yaml > /var/log/crowdsec.log 2>&1 &"
        ], check=True)

        subprocess.run([
            "docker", "exec", "-u", "root", "lamp-server",
            "bash", "-c",
            "nohup crowdsec-firewall-bouncer -c /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml > /var/log/bouncer.log 2>&1 &"
        ], check=True)

    except subprocess.CalledProcessError as e:
        print(f"[!] Erreur lors de la réactivation propre de CrowdSec : {e}")

    wait_crowdsec_ready()

    print("[*] Vérification post-réactivation CrowdSec...")
    subprocess.run(["docker", "exec", "-u", "root", "lamp-server", "pgrep", "-af", "crowdsec"], check=False)
    subprocess.run(["docker", "exec", "-u", "root", "lamp-server", "pgrep", "-af", "crowdsec-firewall-bouncer"], check=False)


def wait_crowdsec_ready(timeout=15):
    print("[*] Attente que l'API CrowdSec soit prête...")
    for i in range(timeout):
        try:
            output = subprocess.check_output([
                "docker", "exec", "-u", "root", "lamp-server", "curl", "-s", "http://127.0.0.1:8080/health"
            ], text=True)
            if '"status":"ready"' in output:
                print(f"[+] API CrowdSec prête après {i+1} secondes")
                return
        except subprocess.CalledProcessError:
            pass
        time.sleep(1)
    print("[!] API CrowdSec NON prête après délai max")


def disable_fail2ban():
    subprocess.run(["docker", "exec", "-u", "root", "lamp-server", "fail2ban-client", "stop"], check=False)
    print("[+] Fail2Ban désactivé temporairement")


def enable_fail2ban():
    subprocess.run(["docker", "exec", "-u", "root", "lamp-server", "fail2ban-client", "start"], check=False)
    print("[+] Fail2Ban réactivé")


def is_http_reachable(url="http://lamp-server", timeout=3):
    try:
        r = requests.get(url, timeout=timeout)
        print(f"[DEBUG] GET {url} → {r.status_code}")
        return r.status_code == 200
    except Exception as e:
        print(f"[DEBUG] Exception is_http_reachable: {e}")
        return False


def get_tcp_metrics():
    try:
        output = subprocess.check_output(["docker", "exec", "-u", "root", "lamp-server", "cat", "/proc/net/netstat"], text=True)
        lines = [line for line in output.splitlines() if "TcpExt:" in line]
        if len(lines) >= 2:
            headers = lines[0].replace("TcpExt:", "").strip().split()
            values = lines[1].replace("TcpExt:", "").strip().split()
            return dict(zip(headers, map(int, values)))
        else:
            print("[!] get_tcp_metrics : lignes TcpExt insuffisantes")
            return {}
    except Exception as e:
        print(f"[!] Erreur get_tcp_metrics : {e}")
        return {}


def disable_defenses_and_syncookies():
    print("[*] Désactivation Fail2Ban, CrowdSec, et SYN cookies", flush=True)
    subprocess.run(["docker", "exec", "-u", "root", "lamp-server", "pkill", "-f", "fail2ban"], check=False)
    subprocess.run(["docker", "exec", "-u", "root", "lamp-server", "pkill", "-f", "crowdsec"], check=False)
    subprocess.run(["docker", "exec", "-u", "root", "lamp-server", "pkill", "-f", "crowdsec-firewall-bouncer"], check=False)
    subprocess.run(["docker", "exec", "-u", "root", "lamp-server", "sysctl", "-w", "net.ipv4.tcp_syncookies=0"], check=False)
    time.sleep(2)


def was_ip_banned_by_crowdsec(ip):
    try:
        output = subprocess.check_output([
            "docker", "exec", "lamp-server", "cscli", "alerts", "list", "-o", "raw"
        ], text=True)
        return ip in output
    except subprocess.CalledProcessError as e:
        print(f"[!] Erreur dans was_ip_banned_by_crowdsec: {e}")
        return False


def apply_crowdsec_ratelimit_ban(bantime):
    try:
        jail_file = "/etc/crowdsec/profiles.yaml"
        subprocess.run([
            "docker", "exec", "-u", "root", "lamp-server",
            "sed", "-i", f"s/duration: .*$/duration: {bantime}s/", jail_file
        ], check=True)
        print(f"[+] Profil CrowdSec mis à jour avec duration: {bantime}s")
    except subprocess.CalledProcessError as e:
        print(f"[!] Impossible d’ajuster la durée de ban CrowdSec : {e}")


def enable_nginx_ratelimit():
    try:
        subprocess.run([
            "docker", "exec", "-u", "root", "lamp-server",
            "bash", "-c",
            "echo 'limit_req_zone $binary_remote_addr zone=one:10m rate=5r/s;' > /etc/nginx/conf.d/ratelimit.conf && "
            "echo 'limit_req zone=one burst=10 nodelay;' > /etc/nginx/conf.d/ratelimit_in_use.conf && "
            "nginx -s reload"
        ], check=True)
        print("[+] Rate limit NGINX activé")
    except subprocess.CalledProcessError as e:
        print(f"[!] Erreur enable_nginx_ratelimit : {e}")


def disable_nginx_ratelimit():
    try:
        subprocess.run([
            "docker", "exec", "-u", "root", "lamp-server",
            "rm", "-f", "/etc/nginx/conf.d/ratelimit_in_use.conf"
        ], check=True)
        subprocess.run([
            "docker", "exec", "-u", "root", "lamp-server",
            "nginx", "-s", "reload"
        ], check=True)
        print("[+] Rate limit NGINX désactivé")
    except subprocess.CalledProcessError as e:
        print(f"[!] Erreur disable_nginx_ratelimit : {e}")


def disable_fail2ban():
    try:
        subprocess.run([
            "docker", "exec", "-u", "root", "lamp-server",
            "fail2ban-client", "stop"
        ], check=True)
        print("[+] Fail2Ban désactivé temporairement")
    except subprocess.CalledProcessError as e:
        print(f"[!] Erreur disable_fail2ban : {e}")


def enable_fail2ban():
    try:
        subprocess.run([
            "docker", "exec", "-u", "root", "lamp-server",
            "fail2ban-client", "start"
        ], check=True)
        print("[+] Fail2Ban réactivé")
    except subprocess.CalledProcessError as e:
        print(f"[!] Erreur enable_fail2ban : {e}")

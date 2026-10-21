FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Mise à jour du système et installation des outils de base
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
    gnupg2 \
    lsb-release \
    iproute2 \
    iputils-ping \
    net-tools \
    vim \
    nano \
    sudo \
    apache2 \
    php \
    libapache2-mod-php \
    nginx \
    fail2ban \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Création d’un utilisateur non-root
RUN useradd -ms /bin/bash devuser && echo "devuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Copie du script de setup
COPY setup_docker.sh /usr/local/bin/setup_docker.sh
RUN chmod +x /usr/local/bin/setup_docker.sh

# Par défaut, root pour permettre l'exécution iptables
USER root
WORKDIR /root

CMD ["/bin/bash", "-c", "/usr/local/bin/setup_docker.sh || true && tail -f /dev/null"]



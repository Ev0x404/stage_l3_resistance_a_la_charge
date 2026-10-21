#!/bin/bash

IMAGE_NAME=lamp-server-fail2ban
CONTAINER_NAME=lamp-server
DOCKERFILE=Dockerfile  # Ton Dockerfile s'appelle bien Dockerfile

# Créer le réseau si nécessaire
docker network inspect reseau-test >/dev/null 2>&1 || {
  echo "[+] Création du réseau Docker 'reseau-test'"
  docker network create reseau-test
}

# Construire l'image si nécessaire
if ! docker image inspect $IMAGE_NAME >/dev/null 2>&1; then
  echo "[+] Construction de l’image $IMAGE_NAME..."
  docker build -t $IMAGE_NAME -f $DOCKERFILE .
else
  echo "[✓] Image $IMAGE_NAME déjà présente"
fi

# Supprimer ancien conteneur s’il existe
docker rm -f $CONTAINER_NAME 2>/dev/null || true

# Lancer le conteneur avec les bonnes permissions
docker run -dit \
  --name $CONTAINER_NAME \
  --hostname $CONTAINER_NAME \
  --network reseau-test \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  --cap-add=SYS_ADMIN \
  -p 7080:80 \
  $IMAGE_NAME
# Prérequis
Avant toute choses, une fois le projet ouvert dans VsCode, assurez vous de créer l'environnement virtuel et d'installer les bibliothèques :

#### Windows
>1) Création du Venv : python -m venv .venv
>2) Activation : .\\.venv\Scripts\Activate.ps1
>3) Installation python -m pip install -r requirements.txt

#### Mac/Linux
>1) Création du Venv : python3 -m venv .venv
>2) Activation : source .venv/bin/activate   
>3) Installation python3 -m pip install -r requirements.txt

# Installation du Raspberry PI
>1) Brancher la carte SD du Raspberry et lancer Pi Imager. Installer la version **"Raspberry PI OS Lite 64 bit"** (La version Lite se trouve dans la section "Raspberry Pi OS (other)).

>2) Ensuite, sélectionner le stockage et cliquer sur suivant. Vous allez maintenant modifier les paramètres **"Modifer réglages"**. Cocher **"Définir nom d'utilisateur et mot de passe"** (*nom d'utilisateur : **raspberry** | mot de passe : **1234***). Cocher, **"Définir les réglages locaux"** et mettre en Fuseau horaire **"Europe/Paris"** et en type de clavier **"fr"**. Cliquer sur l'onglet **"SERVICES"**, cocher **"Activer SSH"** et sélectionner **"Utiliser un mot de passe pour l'authentification"**. Enfin, cliquer sur **"Enregistrer"** et lancer l'installation.

>3) Une fois l'intallation terminée, vous pouvez lancer votre raspberry. (Assurez vous de l'avoir connecté en ethernet (nous v'avons pas mis le wifi dans notre configuration)). Entrer le login et le mot de passe (cf ci-dessus)

>4) Récupérer l'adresse ip de votre raspberry et changer l'ip dans le script bash. Lancer à présent le scrit shell de setup **"setup_raspberry.sh"** depuis votre machine hôte fin que le raspberry se configure automatiquement. Entrez **"yes"** à la question **"Are you sure you wnt to continue connecting"** et entrez ensuite le mot de passe (le même que pour le compte : **1234**). L'installation va se faire, attendez la fin d'exécution

>6) Vous pouvez lancer vos tests tout est prêt ! (Pensez à changer l'ip du raspberry dans les tests si jamais elle est différente de celle mise par défaut)

>7) Notez tout de même qu'il faudra RELANCER LE SCRIP **"setup_raspberry.sh"** à CHAQUE redémarrage du raspberry pour s'assurer de la bonne mise en place des configurations, services, ...

  
# Intallation pour Docker
>1) Commencez par lancer Docker Desktop.
>2) Placez vous dans le projet VsCode, ouvrez un terminal et exécutez le script bash "start.sh" pour démarrer le conteneur avec le serveur
>3) Le script "stop.sh" permet d'arrêter le serveur en supprimant le conteneur. En cas de problème n'hésitez pas à tout reconstruire en supprimant les conteneurs et images générés via Docker Desktop.
>4) Vous devez posséder l'extension "Dev Container" sous VsCode. Cliquez ensuite sur le bouton avec les 2 chevrons (> et <) en bas à gauche de VsCode et sélectionner l'option "Rouvrir dans le conteneur". Ceci va ouvrir le projet dans le conteneur attaquant pour lancer vos tests Docker.
>5) Pour ressortir du conteneur, cliquez sur le même bouton et "Rouvrir le dossier localement".

---
---
---
  
# Conclusion sur Test Syn flood sur Raspberry (Notes dans le cadre du projet)
- Mise en place de 2 tests (avec et sans les cookies). On peut faire les observations suivantes :

### Test d'impact d'une attaque SYN flood sur un serveur Apache

| Paramètre                     | Sans SYN cookies         | Avec SYN cookies          |
|------------------------------|--------------------------|---------------------------|
| SYN cookies activés          | **NON (0)**                   | **OUI (1)**                   |
| Requête HTTP                 | **ÉCHEC (timeout)**       | **RÉUSSITE**               |
| Temps HTTP (pendant attaque) | —                        | ~0.41 s                   |
| `ListenDrops` (Δ)            | **+72 707**              | **0**                     |
| `SyncookiesSent` (Δ)         | 0                        | **+65 907**               |
| Interprétation               | Le noyau rejette des connexions car la file est pleine. | Le noyau protège efficacement en absorbant les SYN. |


**=> _Ainsi, on observe un échec de la requête si les syn cookies ne sont pas activés. Or, quand ils le sont, on observe que la requête est légèrement ralenti mais qu'elle passe correctement. Donc, les syn cookies sont déjà une première protection du kernel face aux syn flood._**



# Conclusion sur l'ajout du module kernel SynProxy
- Mise en place de 3 tests, mais notamment 1 test de comparaison entre uniquement les syn_cookies d'activés et avec l'ajout du SynProxy

| Paramètre                     | SYN Cookies Seuls         | SYNPROXY + Cookies         |
|------------------------------|---------------------------|----------------------------|
| SYN cookies activés          | **OUI (1)**               | **OUI (1)**                |
| Requête HTTP                 | **RÉUSSITE**              | **RÉUSSITE**               |
| Temps HTTP (pendant attaque) | ~0.91 s                   | ~0.42 s                    |
| `ListenDrops` (Δ)            | **+1**                    | **0**                      |
| `SyncookiesSent` (Δ)         | **+60 426**               | **0**                      |
| Interprétation               | Le noyau protège, mais en déclenchant massivement les SYN cookies, ce qui ralentit les requêtes. | SYNPROXY filtre en amont et évite le recours aux SYN cookies, assurant une meilleure fluidité. |

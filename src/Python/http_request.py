# Fichier mettant à disposition des fonctions pour permettre la communication avec le serveur Apache

import requests, time, concurrent.futures

# Fonction permettant d'effectuer une requête vers le serveur Apache et de mesurer le temps de réponse
def request_apache_server(method, delai, url_cible):
    # On stocke l'heure de départ avant envoie de la requête pour mesurer le temps total de la requête
    start_time = time.time()
    # Envoie de la requête et réception de la réponse
    response = requests.post(url_cible, json={"methode" : method, "delai" : delai})
    
    # Vérification du code de retour pour savoir s'il y a eu une erreur (le code 200 signifie un succès)
    if (response.status_code == 200):
        return {
            "etat": "succès",
            "temps_total": time.time() - start_time,
            "donnees": response
        }
    # Si le code n'est pas 200, c'est qu'il y a une erreur
    else:
        return {
            "etat": "échec",
            "temps_total": time.time() - start_time
        }

# Fonction permettant d'exécuter 
def requetes_concurrentes_serveur_apache(nb_requests, method, delai):
    # Affichage en console lors du lancement du test
    print(f"[!] Test vers le serveur Apache lancé avec {nb_requests} requêtes concurrentes (méthode : {method} | délai : {delai})...")
    
    # Liste pour stocker les résultats des requêtes
    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=nb_requests) as executor:
        # Création d'une liste de tâches en cours de réalisation
        futures = [executor.submit(request_apache_server, method, delai) for i in range(nb_requests)]
        
        for future in concurrent.futures.as_completed(futures):
            # On stocke le résultat courant
            result = future.result()
            results.append(result)
        
        # Analyse des résultats pour déterminer le nombre de succès et d'échecs
        nb_succes = sum(1 for resultat in results if resultat["etat"] == "succès")
        nb_echecs = sum(1 for resultat in results if resultat["etat"] == "échec")
        
    return {
        "nb_succes": nb_succes,
        "nb_echecs": nb_echecs
    }
    
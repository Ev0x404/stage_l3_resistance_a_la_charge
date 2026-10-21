<?php
    // Header permettant de définir que l'on va renvoyer du JSON
    header("Content-Type: application/json; charset=utf-8");

    $donnees = json_decode(file_get_contents("php://input"), true);
    $methode = $donnees["methode"] ?? "sleep";  // Récupère la méthode choisi par l'utilisateur. En cas d'échec attribut "sleep" par défaut.
    $delai = (int) $donnees["delai"] ?? 1;  // Récupère le délai choisi par l'utilisateur. En cas d'échec attribut "1" par défaut.

    // On récupère l'heure courante pour définir l'heure de début
    $debut = microtime(true);   // true pour récupérer l'heure sous forme de float correspondant au nombre de secondes

    // On récupère le pid du processus pour pouvoir les différenciés lors du retour
    $pid = getmypid();

    // Si on fait un test en utilisant le "sleep" (bloquage du thread mais libération du cpu)
    if ($methode == "sleep" || $methode == "SLEEP") {
        // Utilisation de la méthode
        sleep($delai);
        // On renvoie les données à l'appelant
        echo json_encode([
            "methode" => "sleep",
            "delai" => $delai,
            "pid" => $pid,
            "duree" => microtime(true) - $debut
        ]);
    }
    // Si on fait un test en attente active avec le while (l'attente active va monopoliser un coeur de processeur à 100%)
    elseif ($methode == "cpu" || $methode == "CPU") {
        // On détermine le temps final pour pouvoir sortir de l'attente active (temps courant + le délai donné)
        $fin = microtime(true) + $delai;
        while(microtime(true) < $fin){
            // Boucle vide pour occupation du cpu pendant le temps donné par l'utilisateur
        }
        echo json_encode([
            "methode" => "cpu",
            "delai" => $delai,
            "pid" => $pid,
            "duree" => microtime(true) - $debut
        ]);
    }
    // Si la méthode entrée n'est pas la bonne
    else {
        echo json_encode([
            "erreur" => "[-] Méthode invalide. Choisissez : \"sleep\" ou \"cpu\"."
        ]);
    }
?>
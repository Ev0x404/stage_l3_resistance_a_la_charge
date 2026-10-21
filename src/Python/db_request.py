# Fichier permettant la communication avec la base de données MariaDB
import mysql.connector, time


# Fonction permettant d'exécuter une requete SQL vers la base de données
def request_MariaDB(time=1):
    start_time = time.time()
    try:
        # Les paramètres suivants peuvent être adaptés suivant ce que l'on a mis en réglages
        connection = mysql.connector.connect(
            host="localhost",
            port=7306,
            user="user1",
            password="user1",
            database="db_projet"
        )
        
        # Création d'un curseur permettant l'interaction avec la base
        cursor = connection.cursor()
        # Exécution de la requête SQL
        cursor.execute(f"SELECT SLEEP({time})")
        # Ici, le fetchall est nécessaire pour attendre la fin de la requête
        cursor.fetchall()

        # On ferme le curseur et la connexion et on retourne
        cursor.close()
        connection.close()
    
        return {
            "etat": "succès",
            "temps": time.time() - start_time
        }
        
    except Exception as e:
        return {
            "etat": "échec",
            "erreur": str(e),
            "temps": time.time() - start_time
        }
PRISE EN MAIN

1) Comment s'appelle cette topology ?
   R = Cette topologie s`appelle client-serveur.

2) Que remarquez vous dans les logs ?
   R = Les messages peuvent etre lus par les personnes
   qui peuvent acceder au serveur

3) Pourquoi est-ce un problème et quel principe cela viole t-il ?

   R = C`est un probleme car le serveur peut avoir acces aux informations personnelles des clients. Cela viole le principe de confidentialite et de securite des donnees.

4) Quelle solution la plus simple pouvez-vous mettre en place pour éviter cela ? Détaillez votre réponse.
   R = Il est necessaire de chiffrer les messages echanges par les clients


CHIFFREMENT

1) Est ce que urandom est un bon choix pour de la cryptographie ? Pourquoi ?

   R = Il peut etre un bon choix car il fait une batterie de tests pour s`assurer
   qu'il produit des nombres aléatoires qui passent les tests statistiques et résistent aux attaques.

2) Pourquoi utiliser ses primitives cryptographiques peut être dangereux ?

   R = Si elles sont mal conçues, ses primitives cryptographiques peut être dangereux
   en possibilitant erreus de conception, vulnerabilites conues et erreur de mise en oeuvre.

3) Pourquoi malgré le chiffrement un serveur malveillant peut il nous nuire encore ?
   R = Parce que il peut faire des attaques par injection, de deni de service, de espionage ou il peut intercepter les communications chiffrees.

4) Quelle propriété manque t-il ici ?
   R = Il n`est pas possible de savoir si le message est authentique, s`il y a eu des
   pertes de donnees.

Authenticated Symetric Encryption

1) Pourquoi Fernet est moins risqué que le précédent chapitre en terme d'implémentation ?
   R = Car Fernet utilise cle de chiffrement plus robuste et il y a l`utilisation de cles secretes uniques pour chaque message.

2) Un serveur malveillant peut néanmoins attaqué avec des faux messages, déjà utilisé dans le
passé. Comment appel t-on cette attaque ?

   R = Cette attaque s`appelle attaque de rejeau ou `replay attack` en anglais

3) Quelle méthode simple permet de s'en affranchir ?
   R = Utiliser de jetons d`authentification uniques pour chaque communication

TTL

1) Remarquez vous une différence avec le chapitre précédent ?
   
   R = Le TimeFernetGUI ajoute une couche supplémentaire de sécurité en appliquant une durée de vie limitée à chaque message chiffré pour limiter les attaques de rejeu.

2) Maintenant soustrayez 45 au temps lors de l'émission. Que se passe t-il et pourquoi ?

   R = Soustraire 45 au temps lors de l'émission signifie que le temps utilisé pour le cryptage (l'horodatage) sera en avance de 45 secondes par rapport à l'heure réelle. 

3) Est-ce efficace pour se protéger de l'attaque du précédent chapitre ?

   R = Oui, en raison d`utiliser un horodatage dans le cryptage, il peut etre efficace pour proteger contre l`attaque de rejeu.

4 ) Quelle(s) limite(s) cette solution peut rencontrer dans la pratique ?

   R = les limites que cette solution peut rencontrer sont la dependence au temps systeme, la duree de vie de messages qui est limitee par le TTL, et la possibilite de les cles etre compromises.

   REGARD CRITIQUE

   Meme avec tout le cryptage effectue, il est toujours possible dee subir des attaques, telles que l`attaque de rejeu. Pour le cas TTL, un attaquant pourrait jouer  avec le temps
   systeme, ou tenter de le deviner. 
   L`utilisation de bibliotheques et de frameworks securises et a jour peut ameliorer le chiffrement. De plus, il est toujours bon d`utiliser des mots de passe longs et complexes,
   car la cle de cryptage est derivee du mot de passe.
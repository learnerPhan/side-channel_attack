############Authors############
Merah-Nguyen-YU(Chenle)




Pour exécuter une attaque sur AES sans contremesure:
$make 
$./main aes_traces.csv

Notez qu'il est nécessaire de garder le MACRO NRES inférieur ou égal à 6000 dans sca.h


Pour exécuter une attaque sur AES avec contremesure:
$make
$./main Xaes_traces.csv

Pour d'autres tests d'attaque sur AES avec contremesure, veuillez donner le nom de fichier des traces commençant par 'X'. De même raison, pour éviter toute erreur de segmentation, il faut que le MACRO NRES soit inférieur ou égal à 6000 dans sca.h




Pour exécuter une attaque sur IDEA:
$make
$./main  (Ceci prend un peu de temps, environ 1h)

Les noms des fichiers d'IDEA sont dans la liste "idea_filename" de sca.h. Notez qu'il est nécessaire de mettre le nombre de traces à 500 (NRES=500)

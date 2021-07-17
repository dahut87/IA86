```

 █████   █████████    ████████    ████████ 
░░███   ███░░░░░███  ███░░░░███  ███░░░░███
 ░███  ░███    ░███ ░███   ░███ ░███   ░░░ 
 ░███  ░███████████ ░░████████  ░█████████ 
 ░███  ░███░░░░░███  ███░░░░███ ░███░░░░███
 ░███  ░███    ░███ ░███   ░███ ░███   ░███
 █████ █████   █████░░████████  ░░████████ 
░░░░░ ░░░░░   ░░░░░  ░░░░░░░░    ░░░░░░░░ 
THE EVEN MORE PEDAGOGICAL SYSTEM !!

Episode 1 : Apprendre l'assembleur X86
```

## Descriptif 

IA86 est un logiciel pour apprendre l'assembleur et la programmation système. Celui-ci se présente sous la forme d'un jeu assorti de plusieurs niveaux à la difficulté croissante. Progressivement le joueur acquier les concepts fondamentaux de l'informatique système au travers des différents défis à relever. Une machine virtuelle permet de vérifier que le code écrit par le joueur rempli les objectifs du niveau.

## Structure

Ecrit en C++, IA86 s'appuie sur la célèbre trilogie de librairies :
* Capstone (Désassembleur) - https://www.capstone-engine.org/
* Keystone (Assembleur) - https://www.keystone-engine.org/
* Unicore (Emulateur de processeur) - https://www.unicorn-engine.org/

L'interface est basée sur un système de fenêtre en terminal afin de préserver un style "ancien système" (librairie FinalCut, f - https://github.com/gansm/finalcut).

## Developpement

La compilation du logiciel s'opère par g++ au travers d'un conteneur docker afin d'assurer de disposer d'un environnement de compilation sur mesure et d'une reproductibilité totale. Un makefile permet de centraliser les différentes tâches au sein d'un même fichier.

Pour compiler
```
make all
```

Pour lancer le logiciel
```
make rerun
```

ou 

```
./start.sh"
```

En mode déboguage (avec plus d'informations)
```
make redebug
```

ou 

```
./start.sh debug"
```



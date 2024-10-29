
# Attaque DES

Ce projet implémente une attaque par faute sur le chiffrement DES, dans le but d'extraire une clé secrète à partir de textes chiffrés avec erreurs. Il utilise des opérations de XOR, permutations et substitutions, ainsi qu'une méthode de bruteforce pour découvrir les bits manquants dans la clé.

## Structure du projet

- **attaque.py** : Contient les fonctions principales pour exécuter l'attaque, incluant les méthodes pour manipuler les chaînes binaires, gérer les permutations, et appliquer les transformations nécessaires.
- **utilitaires.py** : Fournit les outils nécessaires pour le chiffrement et le déchiffrement DES, y compris les tables de permutations, les tables de S-boxes, et les méthodes de conversion entre formats binaires et hexadécimaux.

## Fonctionnalités principales

1. **Génération de Clés par Faute** : Comparaison entre les textes chiffrés corrects et erronés pour identifier les différences.
2. **Attaque par Faute sur la Clé** : Utilisation de différences observées pour restreindre les valeurs possibles de sous-clés dans le DES.
3. **Bruteforce des Bits Manquants** : Itération sur toutes les combinaisons de bits pour compléter la clé partiellement découverte.
4. **Chiffrement DES** : Vérification des hypothèses de clé via des opérations de chiffrement et de comparaison.

## Fichiers de Données

- **chiffre_faux** : Liste des textes chiffrés contenant des erreurs.
- **chiffre** : Texte chiffré correct correspondant.
- **clair** : Texte en clair d'origine.

Vous pouvez utiliser ce projet avec vos propres données en modifiant les variables `chiffre_faux`, `chiffre` et `clair` dans `attaque.py`.

## Documentation

Une documentation détaillée du projet est disponible dans le fichier **Documentation.pdf**.

## Exemple d'exécution

```bash
python attaque.py
```

Le programme affichera :
1. La clé K16 obtenue partiellement.
2. Les 48 bits de clé générés.
3. La clé finale si elle est trouvée.

## Prérequis

- Python 3.6+
- [PyCryptodome](https://pycryptodome.readthedocs.io/) : Bibliothèque pour les opérations DES.

Pour installer PyCryptodome :
```bash
pip install pycryptodome
```

## Détails de l'implémentation

### attaque.py
Le fichier **attaque.py** contient les étapes d'analyse des erreurs pour inférer la clé DES. Les fonctions principales incluent :
- `attaque()`
- `xor_strings()`
- `test_key_combination()`

### utilitaires.py
Le fichier **utilitaires.py** contient des outils essentiels pour l'attaque, tels que :
- Tables de permutations et S-boxes
- Conversion hexadécimal vers binaire et inverse
- Génération de bits de parité

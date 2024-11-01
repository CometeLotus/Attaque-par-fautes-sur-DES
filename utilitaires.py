from Crypto.Cipher import DES
def permutation_initiale(bits):
    # Tableau IP (Initial Permutation)
    table_IP = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]

    # Vérification si la longueur de bits est égale à 64
    if len(bits) != 64:
        raise ValueError("La chaîne de caractères doit contenir exactement 64 bits.")

    # Initialisation de la chaîne de résultat
    resultat = ''

    # Application de la permutation initiale
    for index in table_IP:
        resultat += bits[index - 1]

    return resultat

def permutation(bits):
    # Vérification si la longueur de bits est égale à 32
    if len(bits) != 32:
        raise ValueError("La chaîne de caractères doit contenir exactement 32 bits.")

    # Table de permutation P
    permutation_table = [
        16, 7,  20, 21,
        29, 12, 28, 17,
        1,  15, 23, 26,
        5,  18, 31, 10,
        2,  8,  24, 14,
        32, 27, 3,  9,
        19, 13, 30, 6,
        22, 11, 4,  25
    ]

    # Appliquer la permutation P
    result = ""
    for index in permutation_table:
        result += bits[index - 1]

    return result

def inverse_permutation(bits):
    if len(bits) != 32:
        raise ValueError("La chaîne de caractères doit contenir exactement 32 bits.")
    
    # Table inverse de P
    inverse_p_table = [
        9, 17, 23, 31, 13, 28, 2, 18,
        24, 16, 30, 6, 26, 20, 10, 1,
        8, 14, 25, 3, 4, 29, 11, 19,
        32, 12, 22, 7, 5, 27, 15, 21
    ]
    
    result = ""
    for index in inverse_p_table:
        result += bits[index - 1]

    return result

def s_box(input_bits, s_box_number):
    # Vérification si la longueur de bits est égale à 6
    if len(input_bits) != 6:
        raise ValueError("La chaîne de caractères doit contenir exactement 6 bits.")

    # Définition des S-boxes du DES
    s_boxes = [
        # S-box 1
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ],
        # S-box 2
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
        ],
        # S-box 3
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
        ],
        # S-box 4
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
        ],
        # S-box 5
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
        ],
        # S-box 6
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
        ],
        # S-box 7
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
        ],
        # S-box 8
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
        ]
    ]

    # Convertir les bits d'entrée en indice de ligne et de colonne pour accéder à la valeur de substitution
    row = int(input_bits[0] + input_bits[5], 2)
    column = int(input_bits[1:5], 2)

    # Obtenir la valeur de substitution de la S-box
    substitution_value = s_boxes[s_box_number][row][column]

    # Convertir la valeur de substitution en binaire sur 4 bits
    output_bits = format(substitution_value, '04b')

    return output_bits

def hexa_a_bin(chaine_hexa):
    decimal = int(chaine_hexa, 16)
    chaine_bin = bin(decimal)[2:]
    chaine_bin = chaine_bin.zfill(64)
    return chaine_bin

def binary_to_hex(data):
    # Vérifier si l'entrée est de type bytes
    if isinstance(data, bytes):
        return data.hex().upper()  # Convertir directement en hexadécimal

    # Si c'est une chaîne binaire, alors continuer la conversion comme précédemment
    decimal = int(data, 2)
    hex_str = hex(decimal)[2:]  # Remove '0x' prefix
    return hex_str.upper()


def expansion(bits):
    # Vérification si la longueur de bits est égale à 32
    if len(bits) != 32:
        raise ValueError("La chaîne de caractères doit contenir exactement 32 bits.")

    # Table d'expansion E
    expansion_table = [
        32, 1,  2,  3,  4,  5,
        4,  5,  6,  7,  8,  9,
        8,  9,  10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ]

    # Appliquer la table d'expansion E
    result = ""
    for index in expansion_table:
        result += bits[index - 1]

    return result

def increment_bits(bits):
    # Vérifier si la chaîne contient uniquement des caractères '0' et '1'
    if not all(c in '01' for c in bits):
        raise ValueError("La chaîne de caractères doit contenir uniquement des bits (0 ou 1).")
    
    # Convertir la chaîne de bits en un entier
    num = int(bits, 2)
    
    # Incrémenter le nombre binaire
    num += 1
    
    # Calculer la longueur originale de la chaîne de bits
    original_length = len(bits)
    
    # Convertir le nombre incrémenté en chaîne binaire de la même longueur
    result = format(num, f'0{original_length}b')
    
    return result

def apply_parity_bits(cle_48bits):
    for i in range(0, len(cle_48bits), 8):
        octet = cle_48bits[i:i+8]
        nb_des_1 = octet.count('1')
        cle_48bits[i+7] = '1' if nb_des_1 % 2 == 0 else '0'
    return cle_48bits

def chiffrement_DES(key, clair):
    cipher = DES.new(key, DES.MODE_ECB)
    # Convertir `clair` en bytes et ajouter un padding si nécessaire
    clair_bytes = int(clair, 2).to_bytes(8, byteorder='big')
    encrypted_data = cipher.encrypt(clair_bytes)
    return encrypted_data

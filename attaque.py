from itertools import product
from utilitaires import *

# Textes chiffrés incorrects et texte chiffré juste
chiffre_faux = ["D2FA53AC4FB9A7C2", "92E2C1B50FA8E7C2", "B2E251A50BA8A6C3", "12EA40B54FBCE3E2", 
                "93EB45A51FA827C4", "93EA04A54FBE87C2", "D3EA55A407BAA7C3", "92EA41856BBCA7C2", 
                "93FAC5F74FBDE7C2", "92E861E54BBDA682", "9AE845E41FB9A7C2", "F2EA51A54BFCA78A",
                "92FB00A54FBD8752", "92EF51A54F7CAFC2", "93FF41E15D3DA7C2", "D2EA41AC07ECA7C2",
                "92EB61354ABCE292", "926A49B40EBCA3C2", "906E41B14EBDA3C6", "9AAA41A41FACA7C0",
                "86EA10A54EFCABE2", "96AA44A55F9CA5C2", "96EA40A5CE9CE3D6", "93AA45A35DBCA7C2",
                "86EA08840BBCB782", "92DA43A54BBDB7C2", "06CA40B54ABCB7C2", "90FA41E54FBCA756",
                "D2AA45A55FBCA48B", "92EB51A54FB427C7", "82EA10A56FB4B683", "92EE4125CFBCA3D2"]
                
chiffre = "92EA41A54FBCA7C2"
clair   = "85F26EAB1F0BEF49"



def xor_strings(string1, string2):
    # Initialiser la chaîne résultante
    result = ""

    # Déterminer la longueur minimale entre les deux chaînes
    min_length = min(len(string1), len(string2))

    # Effectuer l'opération XOR bit à bit pour la longueur minimale
    for bit1, bit2 in zip(string1[:min_length], string2[:min_length]):
        # Convertir les bits en entiers et effectuer l'opération XOR
        result += str(int(bit1) ^ int(bit2))

    # Ajouter les bits restants de la chaîne la plus longue
    if len(string1) > len(string2):
        result += string1[min_length:]
    elif len(string2) > len(string1):
        result += string2[min_length:]

    return result


def attaque(chiffree_faux_hexa):
    chiffree_juste_hexa =  ' '.join(chiffre[i:i+2] for i in range(0, len(chiffre), 2))
                          
    chiffree_juste_hexa = chiffree_juste_hexa.replace(" ", "")
    chiffree_faux_hexa  = chiffree_faux_hexa.replace(" ", "")

    chiffree_juste_bin = hexa_a_bin(chiffree_juste_hexa)
    chiffree_faux_bin  = hexa_a_bin(chiffree_faux_hexa)
    resultat_juste = permutation_initiale(chiffree_juste_bin)
    resultat_faux  = permutation_initiale(chiffree_faux_bin)

    r_16 = resultat_juste[0:32]
    r_15= l_16 = resultat_juste[32:]

    r_16_avec_faute = resultat_faux[0:32]
    r_15_avec_faute = l_16_avec_faute = resultat_faux[32:]

    faute = xor_strings(l_16, l_16_avec_faute)
    
    #####################################################
    k_16_6bits = "0" * 6
    k_16 = [[] for _ in range(8)]

    #tmp = inverse_permutation(xor_strings(l_16, l_16_avec_faute))
    tmp = inverse_permutation(xor_strings(r_16, r_16_avec_faute))
    liste = [tmp[i*4:i*4+4] for i in range(8)]
    
    r_15 = expansion(r_15)
    r_15_avec_faute = expansion(r_15_avec_faute)
    
    r_15_6 = [r_15[i*6:i*6+6] for i in range(8)]
    r_15_avec_faute_6 = [r_15_avec_faute[i*6:i*6+6] for i in range(8)]
    
    
    while k_16_6bits != "1000000":

        resultat = []
    
        for i in range(8):
            tmp1 = s_box(xor_strings(r_15_6[i], k_16_6bits), i)
            tmp2 = s_box(xor_strings(r_15_avec_faute_6[i], k_16_6bits), i)
            resultat.append(xor_strings(tmp1, tmp2))

            if liste[i] == resultat[i] and liste[i] != "0000":
                k_16[i].append(k_16_6bits)
              
        
        k_16_6bits = increment_bits(k_16_6bits)
    
    return k_16


def inverse_pc2(bits):
    if len(bits) != 48:
        raise ValueError("La chaîne de caractères doit contenir exactement 48 bits.")
    inverse_pc2_table = [5 , 24, 7 , 16, 6 , 10 , 20, 
                         18, ' ', 12, 3 , 15, 23, 1 , 
                         9 , 19, 2 , ' ', 14, 22, 11, 
                         ' ', 13, 4 , ' ', 17, 21, 8 , 
                         47, 31, 27, 48, 35, 41, ' ', 
                         46, 28, ' ', 39, 32, 25, 44, 
                         ' ', 37, 34, 43, 29, 36, 38, 
                         45, 33, 26, 42, ' ', 30, 40]

    resultat = ""
    for index in inverse_pc2_table:
        if index != ' ':
            resultat += bits[index - 1]
        else:
            resultat += ' '
            
    return resultat


def inverse_pc1(bits):
    if len(bits) != 56:
        raise ValueError("La chaîne de caractères doit contenir exactement 56 bits.")
    
    inverse_pc1 = [8, 16, 24, 56, 52, 44, 36, ' ', 
                   7, 15, 23, 55, 51, 43, 35, ' ', 
                   6, 14, 22, 54, 50, 42, 34, ' ', 
                   5, 13, 21, 53, 49, 41, 33, ' ',
                   4, 12, 20, 28, 48, 40, 32, ' ', 
                   3, 11, 19, 27, 47, 39, 31, ' ', 
                   2, 10, 18, 26, 46, 38, 30, ' ', 
                   1,  9, 17, 25, 45, 37, 29, ' ']
    
    
    resultat = ""
    for i in range(64):
        if inverse_pc1[i] != ' ':
            resultat += bits[inverse_pc1[i] - 1]
        else:
            resultat += ' '
            
    return resultat


def bits_to_bytes(bits):
    # Vérifier que la chaîne de bits contient uniquement '0' et '1'
    if not all(c in '01' for c in bits):
        raise ValueError("La chaîne de caractères doit contenir uniquement des bits (0 ou 1).")

    # Ajouter des zéros initiaux pour que la longueur des bits soit un multiple de 8
    bits = bits.zfill((len(bits) + 7) // 8 * 8)

    # Convertir la chaîne de bits en un entier
    num = int(bits, 2)

    # Convertir l'entier en une séquence de bytes
    byte_array = num.to_bytes((len(bits) + 7) // 8, byteorder='big')

    # Convertir la séquence de bytes en une chaîne de caractères représentant les octets en décimal
    byte_string = ' '.join(str(byte) for byte in byte_array)

    return byte_string


    
dic = {}
tmp = "chiffré"

for i in range(32):
    dic[tmp+str(i)] = attaque(chiffre_faux[i])

k_16 = ""
for i in range(8):
    sets = []
    for k in dic.keys():
        if len(dic[k][i]) != 0:
            sets.append(set(dic[k][i]))
     
    common_elements = set.intersection(*sets)
    common_elements_str = ''.join(map(str, common_elements))
    k_16 += common_elements_str

print("La clé K16: {}".format(binary_to_hex(k_16)))
    
tmp = inverse_pc2(k_16)
cle_48bits = inverse_pc1(tmp)
cle_48bits = cle_48bits.replace(' ', '*')

print("Les 48 bits de la clé: {}".format(cle_48bits))

cle_48bits = list(cle_48bits)

_8bits = '0'* 8
# Textes chiffrés et clair, clé partielle calculée par l'attaque
clair = hexa_a_bin(clair)  # Converti en binaire pour le test de chiffrement
cle_48bits = ['0' if bit == '*' else bit for bit in cle_48bits]  # Remplace '*' avec '0' dans cle_48bits pour tester les combinaisons

def test_key_combination(cle_48bits, clair, chiffre):
    """Essaie différentes combinaisons pour les bits non spécifiés ('*') de la clé."""
    _8bits = '0' * 8  # Initialisation de la séquence binaire pour les bits inconnus
    while _8bits != '1' * 8:  # Continue jusqu'à tester toutes les combinaisons
        indice = 0
        key = ""
        for i in range(64):
            if cle_48bits[i] == '*' and i % 8 != 0:
                cle_48bits[i] = _8bits[indice]
                indice += 1
        _8bits = increment_bits(_8bits)

        # Ajout de la parité
        nb_des_1 = 0
        for i in range(64):
            if cle_48bits[i] == '1':
                nb_des_1 += 1
            if (i + 1) % 8 == 0:  # Ajoute les bits de parité
                cle_48bits[i] = '0' if nb_des_1 % 2 != 0 else '1'
                nb_des_1 = 0

        # Convertir la clé en bytes et tester
        key = int("".join(cle_48bits), 2).to_bytes(8, byteorder='big')
        encrypted_data = chiffrement_DES(key, clair)
        if binary_to_hex(encrypted_data) == chiffre:
            return key  # Retourne la clé trouvée si elle correspond au texte chiffré
    return None  # Aucun correspondance trouvée



# Fonction de brut force pour tester toutes les combinaisons de bits manquants
def test_key_combination(cle_48bits, clair, chiffre):
    indices_etoiles = [i for i, bit in enumerate(cle_48bits) if bit == '*']
    
    for comb in product('01', repeat=len(indices_etoiles)):
        for idx, bit in zip(indices_etoiles, comb):
            cle_48bits[idx] = bit

        cle_48bits = apply_parity_bits(cle_48bits)
        key = int("".join(cle_48bits), 2).to_bytes(8, byteorder='big')
        encrypted_data = chiffrement_DES(key, clair)
        
        if binary_to_hex(encrypted_data) == chiffre:
            return key
    return None

# Initialisation de l'attaque
dic = {}
for i in range(32):
    dic["chiffré" + str(i)] = attaque(chiffre_faux[i])

k_16 = ""
for i in range(8):
    sets = []
    for k in dic.keys():
        if len(dic[k][i]) != 0:
            sets.append(set(dic[k][i]))
    common_elements = set.intersection(*sets)
    common_elements_str = ''.join(map(str, common_elements))
    k_16 += common_elements_str


tmp = inverse_pc2(k_16)
cle_48bits = inverse_pc1(tmp)
cle_48bits = cle_48bits.replace(' ', '*')
cle_48bits = list(cle_48bits)


# Lancer le brut force sur les bits manquants
key_found = test_key_combination(cle_48bits, clair, chiffre)
if key_found:
    print("Clé trouvée:", binary_to_hex(key_found))
else:
    print("Clé introuvable après avoir testé toutes les combinaisons possibles.")

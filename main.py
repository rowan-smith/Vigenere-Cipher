import string
from typing import List

from utils import CeaserCipher, VigenereCipher

KEY_LENGTH_GUESS = 10  # Guess key length X times

ALPHABET = string.ascii_lowercase  # English Alphabet

# http://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
LETTER_FREQUENCY = {"a": 0.0812,
                    "b": 0.0149,
                    "c": 0.0271,
                    "d": 0.0432,
                    "e": 0.1202,
                    "f": 0.0230,
                    "g": 0.0203,
                    "h": 0.0592,
                    "i": 0.0731,
                    "j": 0.0010,
                    "k": 0.0069,
                    "l": 0.0398,
                    "m": 0.0261,
                    "n": 0.0695,
                    "o": 0.0768,
                    "p": 0.0182,
                    "q": 0.0011,
                    "r": 0.0602,
                    "s": 0.0628,
                    "t": 0.0910,
                    "u": 0.0288,
                    "v": 0.0111,
                    "w": 0.0209,
                    "x": 0.0017,
                    "y": 0.0211,
                    "z": 0.0007}

CIPHERTEXT_RAW = """
bvsibykttovmjmhodedbbvsqcgukxvaxchxmqyigyvkmfwohwmpqcaolmjqosjmlmovsnt 
gldiimxwumrmnbfmelshvxbtihlboqmpwgiemyibntmqarcztlwomsnrhzuibnxwkdcdnh 
zzmtvcvlgexsgpaqolfyjnqdignaxkarqumxvmxwighnmwswkxbelolbgoegvyfxeuxvmb 
goxiimxkkdcdnhzzmtvsblceyoferczeqwxibmfzytlizeinahzuwsxlxbajdukmqomdug 
mayygnybzexfyvhdqvhbxvzkthizkiblwwdxgilwwavwytfifbaqwhbxlgexsgbwmmpzsh 
gmisifwkmcywlxvwxpovhkifmbaitzfmqcitvfwhitixxchbxbzelolxlizhdykywdqhbx 
kmcywlxwkdcdnhzzmtvcvmzmrgzhkumxwigtbflsmtfmfmaymameifylntfwoflhkmpzyw 
iidxwuekmeyznltzqxvyglmzxhimamosavbgmdavivttoyzumxaflszbgixvsmnebzshym 
aifmbmhfmesqcxmgavwygmmpgfsimwsvojabkecgnxfaoscjxkifmbaitzfmqcitvfwtck 
lbzisxmhibtzstyczghchgwzxvybkatefyltvptfiwnkqxvybkuahwzbxlelolxlbtibol 
xbtiaiwbnuirmatzqwhizxvqvonxiidxwuekmeyznllqzgsakhcbwqugxftmpcmwqrjslx 
gbexfovmcdigugwzugvykkmxehchgamqchziidxwwbiizxgcfitqqshmtbusbmhyaggvmx 
kdugsmuxkaqsghkmosajexfrsfakhcbwhbtgnavwhwbduhiuelqfmgqhkbtqshmbwzmbam 
aifezghlbmpzcfitqqshmtbusbmhyaagwymrwdmshmxlovmjmhodedbbvakwhyflidipul 
xlardoueqoossvkgbxcmrlbqqgmnvpmwhbxkamxvyxeomqofhkbtircyyqqlsfefiztive 
bkwimxblbdmpombwzwmmmxuflslxaiefsyggwmxhyfibfspulxbtvsmahtpgfsimwsvoja 
bkmpuikbbtqgiglgyqsnkbkovmjmhakwhyfltuosxxleqspmxkdqxkikxiesbmyhzflwmf 
hafilclmqzkwgiemyibntmqargiylwomsnrhzuibnxwkdcdnhzzmtvcvlgexsgltzqfomx 
wwzxvyvhvoidnhyitsaifhzblwwlxkdihmatzurumvamyihbxfiflsgtmqoezmmkcoxilx 
hnflsjnutugyyrvzkthilrafiamtkmmhskntbqvsatklurunaxpaqcghkxtmqjkhxqvhsu 
nbflshhgtursukbbktfiixzfcczmambvwptmmwimwkrxfsgslmmywrixlvaxofehepitcg 
bbusbiylcolobhfwysfjabayeznahcslhbxgmoigmbmgajhbxawysaikipuwajkhxqvhsm 
hqytzyfxvfegivbmfcclbxvfirwkrxfsultipuggslmmylomghbnishikwhirmrfuqxfcv 
vzkthilrafiamtkmzshmnbbmfzyyhzflwminzbsgytlagqsnatbmfohdpqelsmmhceiomr 
fuqxfcvvzkthilrafiavtlmpxvlxlpaprmrlbqqwhhklqvhivhuyybcvtbqawnavcexcgx 
kauxaolmxawgyllaqtoltmmovmjmhodedbbvsqcgwhkzqwdigwqzkhiwbnrifygmkgwhif 
xzeshbxkeuwswnlbaqsllvizvsuwmpqqsmltoqwqiffczmqumxlnihqxxvflsvtgsmrrim 
amdgimmhuqvg 
"""


def main():
    cipher = VigenereCipher(CIPHERTEXT_RAW)  # create the cipher
    print(f"Ciphertext: {cipher.ciphertext}")

    # get x index of coincidences from x guesses
    ioc_collection = cipher.find_ic_sequences(KEY_LENGTH_GUESS)

    # highest value in index is highest coincidence
    highest_ic = ioc_collection.get_max_index_coincidence()

    # key length is index of highest index of coincidence
    key_length = highest_ic.index
    print(f"Key Length: {key_length}")

    # find all ceaser ciphers for the key length
    ceaser_ciphers = find_ceaser_ciphers(cipher.ciphertext, key_length)

    # find keyword using ciphers
    cipher.find_key(ceaser_ciphers)
    print(f"Keyword: {cipher.keyword}")

    # decrypt cipher using keyword
    cipher.decrypt()
    print(f"Plaintext: {cipher.plaintext}")


# https://medium.com/@0xckylee/cracking-vigen%C3%A8re-cipher-cee60db3a966
def find_ceaser_ciphers(ciphertext: str, key_length: int) -> List[CeaserCipher]:
    cipher_list = []  # cipher array

    for key in range(key_length):  # loop over len of alphabet

        caesar_text = ciphertext[key::key_length]  # create ciphertext
        cipher = CeaserCipher(key, caesar_text, LETTER_FREQUENCY)  # create a Cipher
        cipher_list.append(cipher)

    return cipher_list


main()

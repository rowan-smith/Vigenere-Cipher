import string
from typing import List

from utils import CeaserCipher, IOCSequenceCollection, IndexOfCoincidence


class VigenereCipher:

    def __init__(self, ciphertext: str, keyword: str = ""):
        self.ciphertext_raw = ciphertext
        self.ciphertext = "".join(i.lower() for i in ciphertext if i.isalpha())  # sanitise ciphertext
        self.keyword = keyword
        self.keyword_length = len(self.keyword)
        self.plaintext = ""

    # https://www.dcode.fr/vigenere-cipher#:~:text=To%20decrypt%2C%20take%20the%20first,rank%20of%20the%20plain%20letter.
    def decrypt(self, alphabet: str = string.ascii_lowercase):
        for num, ciphertext_letter in enumerate(self.ciphertext):
            ciphertext_index = alphabet.index(ciphertext_letter)  # get letter index

            keyword_letter = self.keyword[num % self.keyword_length]  # use modulo to get the keyword letter
            keyword_index = alphabet.index(keyword_letter)

            letter_index = ciphertext_index - keyword_index
            if letter_index < 0:
                letter_index += len(alphabet)  # if negative add alphabet length to reset e.g. A becomes Z

            self.plaintext += alphabet[letter_index]  # add letter to plaintext

    def find_key(self, ciphers: List[CeaserCipher] = None) -> str:
        if not self.keyword:  # check if keyword has been found already

            for cipher in ciphers:
                self.keyword += cipher.key_letter  # add key letter to keyword to build keyword

        self.keyword_length = len(self.keyword)
        return self.keyword

    def find_ic_sequences(self, guesses: int = 10) -> IOCSequenceCollection:
        sequence_list = IOCSequenceCollection()  # sequence collection

        # guess key x many times
        for length in range(guesses + 1):  # add 1 to give KEY_LENGTH correct value

            if not length:  # 0 causes slicing error
                continue

            # splice ciphertext by nth character, remove guess amount padding from start
            sequence = IndexOfCoincidence(length, self.ciphertext[length - 1::length])
            sequence_list.add_sequence(sequence)

        return sequence_list

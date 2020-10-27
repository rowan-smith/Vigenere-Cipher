import string
from typing import List, Dict


class CeaserCipher:

    def __init__(self, index: int, ciphertext: str, letter_frequencies: dict, alphabet: str = string.ascii_lowercase):
        self.index = index
        self.ciphertext = ciphertext
        self.ciphertext_length = len(self.ciphertext)
        self.letter_frequencies = letter_frequencies
        self.alphabet = alphabet
        self.key_letter = self.freq_analysis()

    def __str__(self):
        return f"{self.index}, {self.key_letter}, {self.ciphertext_length}, {self.ciphertext}"

    def freq_analysis(self):
        all_chi_square_values = []

        for alphabet_num in range(len(self.alphabet)):  # loop over range of alphabet

            # shift text by alphabet_num
            ciphertext_shift = self.shift_text(alphabet_num)

            # count letter occurrence e.g. A: 7, B: 20, C: 42
            occurrences = self.count_letter_occurrence(ciphertext_shift)

            # find frequency of letters in ciphertext
            occurrence_frequencies = self.get_occurrence_frequencies(occurrences)

            # compare frequency with standard language frequencies to get chi-square value
            chi_square_value = self.find_chi_square_value(occurrence_frequencies)

            # add to chi-square values
            all_chi_square_values.append(chi_square_value)

        # the smallest chi-squared value is the shift of the letter required
        # 26 values (letters), the smallest value is the letter
        # using the value you can find the index position in the alphabet
        smallest_chi_square_value = min(all_chi_square_values)
        letter_index = all_chi_square_values.index(smallest_chi_square_value)

        # turn the letter index into letter
        letter = self.alphabet[letter_index]

        return letter

    def shift_text(self, shift: int, ciphertext: str = None) -> List[str]:
        if not ciphertext:
            ciphertext = self.ciphertext  # if no ciphertext provided use class ciphertext

        ciphertext_shift = []  # shift of letter e.g. B becomes A etc. based on the number in the alphabet
        for letter in ciphertext:
            index = self.alphabet.index(letter) - shift

            if index < 0:
                index += len(self.alphabet)  # if negative add alphabet length to reset e.g. A -> Z, B -> X

            ciphertext_shift.append(self.alphabet[index])

        return ciphertext_shift

    def count_letter_occurrence(self, shifted_ciphertext: List[str]) -> Dict[str, int]:
        occurrences = {}
        for alphabet_count, letter in enumerate(self.alphabet):
            occurrences[letter] = (shifted_ciphertext.count(letter))  # count number of letter occurrences in each shift
        return occurrences

    def get_occurrence_frequencies(self, occurrences: Dict[str, int]) -> Dict[str, float]:
        letter_frequencies = {}
        for letter in self.alphabet:

            # divide letter count in occurrence by total ciphertext length to get letter frequency
            letter_frequency = occurrences[letter] * (1.0 / float(self.ciphertext_length))
            letter_frequencies[letter] = letter_frequency

        return letter_frequencies

    # http://practicalcryptography.com/cryptanalysis/text-characterisation/chi-squared-statistic/
    def find_chi_square_value(self, frequencies: Dict[str, float]) -> float:
        chi_squared_sum = 0.0

        for num, letter in enumerate(self.alphabet):
            letter_frequency = frequencies[letter]
            language_letter_frequency = self.letter_frequencies[letter]

            # (x - y) ** 2 / y
            # compare letter frequency from ciphertext to standard letter frequency of language
            chi_squared_value = (letter_frequency - language_letter_frequency) ** 2 / language_letter_frequency
            chi_squared_sum += chi_squared_value

        return chi_squared_sum

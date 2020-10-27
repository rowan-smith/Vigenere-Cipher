import string
from typing import List


class IndexOfCoincidence:

    def __init__(self, index: int, sequence: str, alphabet: str = string.ascii_lowercase):
        self.index = index
        self.sequence = sequence
        self.alphabet = alphabet
        self.index_coincidence = self.get_index_coincidence()

    def __str__(self):
        return f"IOC: {self.index_coincidence}, Sequence: {self.sequence}"

    # https://pages.mtu.edu/~shene/NSF-4/Tutorial/VIG/Vig-IOC.html
    def get_index_coincidence(self) -> float:
        # 1 / N(N - 1)
        numerator = 1 / (len(self.sequence) * len(self.sequence) - 1)

        # ∑26( (Fi(Fi - 1)) )
        denominator = sum(self.sequence.count(i) * (self.sequence.count(i) - 1) for i in self.alphabet)

        return numerator * denominator


class IOCSequenceCollection:

    def __init__(self):
        self.collection: List[IndexOfCoincidence] = []

    def add_sequence(self, sequence: IndexOfCoincidence) -> None:
        self.collection.append(sequence)

    def get_max_index_coincidence(self) -> IndexOfCoincidence:
        highest_coincidence = max(i.index_coincidence for i in self.collection)
        return [i for i in self.collection if i.index_coincidence == highest_coincidence][0]

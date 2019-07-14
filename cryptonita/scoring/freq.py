'''
Case-sensitive letter and bigram frequency counts
from large-scale English corpora
MICHAEL N. JONES and D. J. K. MEWHORT
Queen’s University, Kingston, Ontario, Canada

https://www.researchgate.net/publication/8090755_Case-sensitive_letter_and_bigram_frequency_counts_from_large-scale_English_corpora

Raw Case-Sensitive Single-Letter Counts
from the NYT Corpus

'''

from ..conv import B
from ..fuzzy_set import FuzzySet

# Format:
# Letter, Uppercase, Lowercase
_tmp = [
'A',280937,5263779,
'B',169474,866156,
'C',229363,1960412,
'D',129632,2369820,
'E',138443,7741842,
'F',100751,1296925,
'G',93212,1206747,
'H',123632,2955858,
'I',223312,4527332,
'J',78706,65856,
'K',46580,460788,
'L',106984,2553152,
'M',259474,1467376,
'N',205409,4535545,
'O',105700,4729266,
'P',144239,1255579,
'Q',11659,54221,
'R',146448,4137949,
'S',304971,4186210,
'T',325462,5507692,
'U',57488,1613323,
'V',31053,653370,
'W',107195,1015656,
'X',7578,123577,
'Y',94297,1062040,
'Z',5610,66423,
]

_utotal = _ltotal = 0
_en_upper_letter_freq, _en_lower_letter_freq, _en_letter_freq = {}, {}, {}
for letter, ucount, lcount in zip(_tmp[::3], _tmp[1::3], _tmp[2::3]):
    _en_upper_letter_freq[B(letter.upper())] = ucount
    _en_lower_letter_freq[B(letter.lower())] = lcount

    _utotal += ucount
    _ltotal += lcount

_en_letter_freq.update(_en_upper_letter_freq)
_en_letter_freq.update(_en_lower_letter_freq)

for freq_by_letter, total in (
        (_en_upper_letter_freq, _utotal),
        (_en_lower_letter_freq, _ltotal),
        (_en_letter_freq, _utotal + _ltotal)):
    for letter in freq_by_letter:
        freq_by_letter[letter] /= total

def en_upper_letter_freq():
    return FuzzySet(_en_upper_letter_freq)

def en_lower_letter_freq():
    return FuzzySet(_en_lower_letter_freq)

def en_letter_freq():
    return FuzzySet(_en_letter_freq)

# Resource
# http://norvig.com/mayzner.html
#
# Format
# Word Length, Count (in millons)
_tmp = [
 1, 22301.22,
 2,131293.85,
 3,152568.38,
 4,109988.33,
 5, 79589.32,
 6, 62391.21,
 7, 59052.66,
 8, 44207.29,
 9, 33006.93,
10, 22883.84,
11, 13098.06,
12,  7124.15,
13,  3850.58,
14,  1653.08,
15,   565.24,
16,   151.22,
17,    72.81,
18,    28.62,
19,     8.51,
20,     6.35,
21,     0.13,
22,     0.81,
23,     0.32,
]

_space_count = sum(c for c in _tmp[1::2])   # aka word count
_letter_count = sum(l*c for l, c in zip(_tmp[::2], _tmp[1::2]))
_space_freq = _space_count / (_space_count + _letter_count)

def etaoin_shrdlu(include_space=True, n=12):
    ''' Frequency of the lowercase letters taken from a set of
        English texts that mixed lowercase and uppercase letters.

        If include_space is True, include the space character in the
        frequency.
    '''
    s = en_lower_letter_freq()
    if include_space:
        s.scale(1-_space_freq)
        s[B(' ')] = _space_freq
        n += 1

    s.cut_off(n=n)
    return s

def tsamcin_brped(n=12):
    ''' Frequency of the uppercase letters taken from a set of English
        texts that mixed lowercase and uppercase letters.

        If you are interested in the frequency of english letters in general
        but your text is uppercase, change it to lowercase and use
        etaoin_shrdlu.

        The space character is not included.
        '''
    s = en_upper_letter_freq()
    s.cut_off(n=n)

    return s

# https://norvig.com/mayzner.html
# Most common n-grams
_tmp = '''
th     the
he     and
in     ing
er     ion
an     tio
re     ent
on     ati
at     for
en     her
nd     ter
ti     hat
es     tha
or     ere
te     ate
of     his
ed     con
is     res
it     ver
al     all
ar     ons
st     nce
to     men
nt     ith
ng     ted
se     ers
ha     pro
as     thi
ou     wit
io     are
le     ess
ve     not
co     ive
me     was
de     ect
hi     rea
ri     com
ro     eve
ic     per
ne     int
ea     est
ra     sta
ce     cti
li     ica
ch     ist
ll     ear
be     ain
ma     one
si     our
om     iti
ur     rat
'''
en_bigrams, en_trigrams = zip(*[line.split() for line in _tmp.strip().split('\n')])


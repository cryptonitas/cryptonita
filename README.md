# ``cryptonita`` - Cryptanalysis Swiss Army Knife

[cryptonita](https://pypi.org/project/cryptonita/) is a set of building
blocks to create automated crypto-attacks.

You may not find the advanced attack implemented here (yet) but I hope
that this building blocks or primitives can help you in your journey.

Without more, let's put our hands on and break the famous
[Vigenere cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher).

## Tutorial - Break a xor Vigenere cipher

The
[Vigenere cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher)
was once the most secure cipher. It was thought that
it was unbreakable...

Let's put under test that statement and learn about
[cryptonita](https://pypi.org/project/cryptonita/)
along the journey!

> Note: the following README is also an automated test for the
> `cryptonita` lib thanks to
> [byexample](https://byexamples.github.io/byexample).

### Implement the cipher - Load the bytes

The building block in `cryptonita` is the *byte string*: a finite
immutable sequence of bytes.

In `cryptonita` we can create a *byte string* with the `B` function
and do any conversion needed:

```python
>>> from cryptonita import B            # byexample: +timeout=10
>>> B(u'from an unicode encoded text', encoding='utf-8')
'from an unicode encoded text'

>>> B([0x46, 0x72, 0x6f, 0x6d, 0x20, 0x6e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x73])
'From numbers'

>>> B('RnJvbSBiYXNlNjQ=', encoding=64)
'From base64'
```

For our purposes of implementing a Vigenere cipher,
let's load some plain text from a file:

```python
>>> ptext = B(open('./test/ds/plaintext', 'rt').read())

>>> ptext[:29]
'Now that the party is jumping'
```

> For the full list of conversions see
> [cryptonita/conv.py's `as_bytes`](https://github.com/cryptonitas/cryptonita/tree/master/cryptonita/conv.py)

### Implement the cipher - Apply a xor

First, we load our secret key in base 64 from the file. Notice how the
decoding from base 64 is made by `B`:

```python
>>> secret = B(open('./test/ds/secret', 'rt').read(), encoding=64)
```

The Vigenere cipher consists in xord the plaintext with the key. If the
plaintext is larger than the key, just repeat the key over and over.

`cryptonita` can do exactly that:

```python
>>> ctext = ptext ^ secret.inf()

>>> ctext[:29].encode(64)
b'OA4ZSRgEAAJBGgEJTBEXExoQTAUSVgsbBBwFDxE='
```

The `inf()` method tells that the `secret` string must be seen as an
"infinite sequence", repeating the key over and over.

Then, the `^` just does the xor byte by byte.

> For the full list of operation on `ImmutableByteString` see
> [cryptonita/bytestrings.py's `ImmutableByteString`](https://github.com/cryptonitas/cryptonita/tree/master/cryptonita/bytestrings.py)
> and the [mixins](https://github.com/cryptonitas/cryptonita/tree/master/cryptonita/mixins.py)

### Breaking the cipher - Scoring the length of the key

Vigenere was thought to be unbreakable because a priori is not possible
to know the length of the key.

However this was proved to be false.

In 1863, [Kasiski](https://en.wikipedia.org/wiki/Kasiski_examination)
came with a cleaver method to know the length of the key but it is quite
hard to make it right and faster (I'm still
[working on it](https://book-of-gehn.github.io/articles/2020/10/11/Kasiski-Test-Part-I.html))

Modern and better approaches are the [Hamming distance](https://en.wikipedia.org/wiki/Hamming_distance)
and the [Index of Coincidence](https://book-of-gehn.github.io/articles/2019/10/04/Index-of-Coincidence.html)

The idea is to assume that the key is of length L and then pick every
Lth byte of the ciphertext:

```python
>>> L = 8 # totally arbitrary here
>>> picked = ctext[::L]
```

> Note how the `ImmutableByteString` ciphertext supports indexing operation like
> any Python string.

Now we compute the Index of Coincidence (IC) of this picked string.

If the assumed length L is **not** the correct one, every picked byte will be the
xor of the plaintext with a different key byte and the whole `picked`
string would like **random** and the IC will be very low.

On the other hand, if we guessed correctly the length L, **all** the picked bytes
will be the xord of the plaintext and the **same** key byte and
therefore will not look random. A high IC would be expected!

```python
>>> from cryptonita.metrics import icoincidences
>>> icoincidences(picked)
0.02<...>
```

> See
> [cryptonita/scoring.py](https://github.com/cryptonitas/cryptonita/tree/master/cryptonita/scoring/score_funcs.py)
> and
> [cryptonita/metrics.py](https://github.com/cryptonitas/cryptonita/tree/master/cryptonita/metrics/__init__.py)

> I you want to know more about the Index of Coincidence see
> this [blog post](https://book-of-gehn.github.io/articles/2019/10/04/Index-of-Coincidence.html) about it
> and this [comparison with other methods](https://book-of-gehn.github.io/articles/2018/04/01/A-string-of-coincidences-is-not-a-coincidence.html)

### Breaking the cipher - Guessing the length of the key


A IC of 0.02 is too low. It seems that 8 is not the length of the key.

We could do a loop to try other lengths but `cryptonita` already has that

```python
>>> from cryptonita.scoring import scoring
>>> from cryptonita.scoring import key_length_by_ic

>>> gklength = scoring(
...                     ctext,
...                     space=range(5, 25),
...                     score_func=key_length_by_ic,
...                     min_score=0.025,
... )
```

Okay, what is that?

 - `scoring` does a brute force *attack* computing a *score
function* testing every possible length from 5 to 25.
 - `key_length_by_ic` is a *scores* how good the tested length is.
It puts a score between 0 (bad) and 1 (good) using the Index of
Coincidence.

You may think that `gklength` is the **the** guessed key but in
cryptoanalysis you mostly never work with a *specific* value. You work
with a **set of possible values**.

```python
>>> gklength
{5: 0.02702702702702703,
 6: 0.027649769585253458,
 7: 0.04682040531097135,
 8: 0.02682701202590194,
 9: 0.025551684088269456,
 10: 0.025604551920341393,
 12: 0.038306451612903226,
 14: 0.03133903133903134,
 16: 0.028985507246376812,
 17: 0.02766798418972332,
 21: 0.032679738562091505,
 24: 0.041666666666666664}
```

In `cryptonita` we call these sets, these *guesses*, `FuzzySet`.

> For more scoring functions see
> [cryptonita/scoring.py](https://github.com/cryptonitas/cryptonita/tree/master/cryptonita/scoring/score_funcs.py)

### Breaking the cipher - A guess as a fuzzy set

A guess or `FuzzySet` is a bunch of possible solutions, each with an
associated probability or score.

We can query then the most likely answer. In our case, the most likely
length of the key:

```python
>>> gklength.most_likely()
7
```

But the most likely may not necessary mean the correct answer. Instead,
you should work always with the fuzzy set to test all of them.

If the sets gets to large (and they will), you can cut them off,
dropping items with a probability lower than some threshold.

Here we say that any length with a lower probability of 0.01 should be
out:

```python
>>> gklength.cut_off(0.03)
>>> gklength
{7 -> 0.0468, 24 -> 0.0417, 12 -> 0.0383, 21 -> 0.0327, 14 -> 0.0313}
```

> Take a look at the
> [documentation of `FuzzySet`](https://github.com/cryptonitas/cryptonita/tree/master/cryptonita/fuzzy_set.py)
> and optional a wiki about [fuzzy set theory](https://en.wikipedia.org/wiki/Fuzzy_set).

### Breaking the cipher - Chop the ciphertext into blocks

Now the we have a set of possible lengths, here is the plan to crack the
cipher:

First, split the ciphertext into *blocks* of guessed length L:

```python
>>> L = gklength.most_likely()
>>> cblocks = ctext.nblocks(L)
```

```
ciphertext:  ABCDEFGHIJKLMN
              |   |    |  |
              |   |    \  \___
              |   |     \     \
cblocks      ABCD  EFGH  IJKL  MN
```

Each first byte of those blocks are supposedly the result of xor the
plaintext with the same key byte. The same goes for the second byte of
each block and so on.

Second, because it is easier to have all the first bytes in one block, all the
second bytes in another block and so on, we want to *transpose* the
blocks:

```python
>>> from cryptonita.conv import transpose
>>> cblocks = transpose(cblocks, allow_holes=True)
```

```
 cblocks   --> transposed cblocks
  ABCD           AEIM
  EFGH           BFJN
  IJKL           CGK
  MN             DHL
```

Now, each block (or row) is a piece of plaintext encrypted with the same
single-byte key.

Let's break it!


### Breaking the cipher - Frequency attack

We could test all the 256 possible byte keys by brute force but that's
quite slow.

Rather we could do a *frequency attack* because the statistics of
the plaintext are leaked into the ciphertext.

`cryptonita` already provides us with a very simple *model* of the
frequencies of the English plaintext: the famous *ETAOIN SHRDLU*.

```python
>>> from cryptonita.scoring.freq import etaoin_shrdlu
```

If our ciphertext has the same distribution than the plaintext, at least
one of the most common bytes in the ciphertext should be one of the
most common bytes in the plaintext, encrypted of course.

Under this hypothesis ``freq_attack`` xor the top most common bytes
in the ciphertext with the most common bytes in plaintext according
to the model.

```python
>>> most_common_pbytes = etaoin_shrdlu()
>>> ntop_most_common_cbytes = 1

>>> from cryptonita.attacks import freq_attack

>>> freq_attack(cblocks[0], most_common_pbytes, ntop_most_common_cbytes)
{'"': 0.07387790762504176,
 '$': 0.055504740275805896,
 '%': 0.0561520934139066,
 '2': 0.03178778752478832,
 '3': 0.10384587375686015,
 '5': 0.026296157563462763,
 '7': 0.07060615929878336,
 '8': 0.060837928943597436,
 '9': 0.0634364224946222,
 ':': 0.0342469273170487,
 '>': 0.03964865941609311,
 '?': 0.06072776315086166,
 'v': 0.17269159612928756}
```

In general, `freq_attack` cannot give us **the** byte key but it can
give use a *guess*: a fuzzy set of possible keys. This is a much shorted
list than 256!

But don't claim victory yet. We broke only the first block (`cblocks[0]`).

> More frequency models may be found at
> [cryptonita/scoring/freq.py](https://github.com/cryptonitas/cryptonita/tree/master/cryptonita/scoring/freq.py)

### Breaking the cipher - Guess explosion

We need to call `freq_attack` for all the blocks:

```python
>>> gbkeys = []
>>> for c in cblocks:
...     gbkeys.append(freq_attack(c, most_common_pbytes, ntop_most_common_cbytes))

>>> len(gbkeys)
7
```

So we have 7 guesses (7 fuzzy sets), one guess set per byte of the key.

But the key is one of the *all possible combination of the guesses*.

How many possible keys do we have?


```python
>>> from cryptonita.fuzzy_set import len_join_fuzzy_sets

>>> len_join_fuzzy_sets(gbkeys)
62748517
```

How! that's a lot! But still **much less than** 256^7 which is greater than
the age of the
[observable universe](https://en.wikipedia.org/wiki/Observable_universe) in years.

Still, we need to shrink the guesses even further to make it manageable.


### Breaking the cipher - Brute force refinement

`freq_attack` is really powerful but it is not the only tool that we
have.

Not all the possible keys in a guess will produce *"reasonable"*
plaintext.

We can *score* a plaintext and filter out the ones that don't look *"good
enough"*

`cryptonita` implements different scoring functions and
`all_ascii_printable` is the most simplest to understand:

Let's *assume* that the plaintext is an English message encoded in ASCII.

If we decipher one block and we got a plaintext with non-printable ASCII
char we can be sure that the key used is incorrect and we can score it
with a `0`. Otherwise, we score it with `1`.

```python
>>> from cryptonita.scoring import all_ascii_printable

>>> all_ascii_printable(B("a reasonable plaintext"))
1

>>> all_ascii_printable(B("n\0t v\4lid"))
0
```

The plan is to try **all** the possible byte keys in **each** of our
guesses, score the results and drop the ones with lower score.

```python
>>> from cryptonita.attacks import brute_force

>>> for i, c in enumerate(cblocks):
...     # the fuzzy set of keys (a guess) for this ith byte
...     gbkey = gbkeys[i]
...
...     refined = brute_force(c,
...                     score_func=all_ascii_printable,
...                     key_space=gbkey,
...                     min_score=0.01
...                 )
...
...     # "refined" is another fuzzy set (a guess) for the ith byte
...     # but probably a much smaller one
...     gbkeys[i] = refined
```

Like ``guess_key_length``, ``brute_force`` receives a score function, a key space
and a minimum score.

Now we have a much smaller search space to work on:

```python
>>> len_join_fuzzy_sets(gbkeys)
260

>>> 260 / 62748517
4.14<...>e-06
```

While still we have a lot of possible keys, the refinement did an
amazing job and the new set is **6 orders of magnitud smaller** than the
original!

We can compute the set of possible keys doing a join and we can even
further reduce the set keeping only the most likely keys:

```python
>>> from cryptonita.fuzzy_set import join_fuzzy_sets
>>> gkstream = join_fuzzy_sets(gbkeys, cut_off=1024, j=B(''))
```

`gkstream` is our guess for the complete key stream for the cipher.

Is this right?

### Breaking the cipher - Break the cipher!

```python
>>> kstream = gkstream.most_likely()

>>> print((ctext ^ kstream.inf()).decode('ascii'))
Now that the party is jumping
With the bass kicked in and the Vega's are pumpin
Quick to the point, to the point, no faking
Cooking MC's like a pound of bacon
Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal
And a high hat with a souped up tempo
I'm on a roll, it's time to go solo
ollin' in my five point oh
ith my rag-top down so my hair can blow


>>> kstream.encode(64)
b'dmFuaWxsYQ=='
```

### Final thoughts

Vigenere or a repeating key cipher is a well known poor cipher shown
in every single cryptography course.

But little is explained in how to break it in an *automated* fashion.

[cryptonita](https://pypi.org/project/cryptonita/)
is not magical and a little of brain is required from you, but it is
a quite useful *Swiss army knife for breaking crypto*.

PRs or comments are welcome.

Tested with [byexample](https://byexamples.github.io/byexample).

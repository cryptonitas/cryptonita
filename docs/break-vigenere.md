# Breaking a repeated key / Vigenere cipher

A [Vigenere cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher)
consists in xor a key with the plaintext.
In general, a plaintext is much longer than the key so the same
key is used again until the plaintext is fully encrypted.

This cipher was consider secure a long time ago and it is well known
that it can be broken.

However, despite of this, modern home-made ciphers and even standard ciphers
when used incorrectly can be seen as complex variants of a Vigenere cipher.

The vulnerability resides in that the key is not a one-time pad but it is
used several times.

Let's break it using [cryptonita](https://pypi.org/project/cryptonita/).

## Load the ciphertext

For this write-up we are going to use a ciphertext taken from the
[Matasano Challenge](https://cryptopals.com/sets/1/challenges/6), now
known as the Cryptopals Challenge.

```python
>>> ciphertext = open('./test/ds/vigenere-ctext', 'rb').read()
```

The unit of work of ``cryptonita`` is the ``ImmutableByteString``:
a class to represent an immutable sequence of bytes.

The ``B`` function is a shortcut to take Python ``unicode`` and ``bytes``
and convert them into ``ImmutableByteString``.

It is quite handy and flexible as it accepts text in base 64 (or other
bases), iterable of integers and raw bytes.

In our case, the ciphertext can be decoded with just one call:

```python
>>> from cryptonita import B            # byexample: +timeout=10

>>> ciphertext = B(ciphertext, 64)
```

## Guess the length of the key

The length of the key used can be arbitrary and it is typically unknown
to the attacker.

This was consider a security feature but there were develop several
algorithms to *guess* the length of the key in the past 100 years.

Some algorithms and heuristics are
the Kasiski Test,
the [Hamming Distance](https://en.wikipedia.org/wiki/Hamming_distance)
and the [Index of Coincidences](https://en.wikipedia.org/wiki/Index_of_coincidence).

These can be found in the ``scoring`` module and
the *guess* algorithm in the ``attacks`` module:

```python
>>> from cryptonita.scoring import key_length_by_ic
>>> from cryptonita.attacks import guess_key_length
```

And putting all this together:

```python
>>> gklength = guess_key_length(
...                         ciphertext,
...                         length_space=40,
...                         score_func=key_length_by_ic,
...                         min_score=0.02
...                         )
```

``guess_key_length`` received the length space where to search: it can
be a list of possible lengths or just a number in which case ``guess_key_length``
will try all the possible lengths from 1 to the given number.

Each length is then evaluated using ``score_func`` and all the lengths with
a score greater than ``min_score`` are returned.

``guess_key_length`` returns a *guess*.

A *guess* in ``cryptonita`` is an object that does not represent a single
value or answer but a *set of possible values or answers*.

This object is implemented using a
[Fuzzy Set](https://en.wikipedia.org/wiki/Fuzzy_set).

```python
>>> len(gklength)
12

>>> klength = gklength.most_likely()
>>> klength
29
```

## Repeating single-byte key

We know that each block of 29 bytes is xored with the same key.

```python
>>> cblocks = ciphertext.nblocks(n=klength)
```

More over, the first byte of all of those blocks is xored with the same
byte key. The same happen with the second byte of each block, the third byte
and so on.

We are working with one byte of each block.

To focus on each byte key at a time, it is more convenient to work
with blocks encrypted with the same byte key.

For this, the ``transpose`` method exists but before we need to
normalize the lengths of the blocks because the last one may be
shorter than 29 bytes.

```python
>>> from cryptonita.conv import uniform_length, transpose

>>> cblocks = uniform_length(cblocks, length=klength)
>>> cblocks = transpose(cblocks)
```

Now each block is encrypted with the same byte key.

## Frequency attack

To perform a *frequency attack* we need to know something about the plaintext.

If we assume that it is an English text encoded as ASCII, we can use the
well known [ETAOIN-SHRDLU](https://en.wikipedia.org/wiki/Etaoin_shrdlu) model:
the 13 top most common letters.

This and other simple models are included in ``cryptonita`` too.

```python
>>> from cryptonita.scoring.freq import etaoin_shrdlu
```

If our ciphertext has the same distribution than the plaintext, at least
one of the most common bytes in the ciphertext should be one of the
most common bytes in the plaintext, encrypted of course.

Under this hypothesis ``freq_attack`` xor the top most common bytes
in the ciphertext with the most common bytes in plaintext according
the model.

```python
>>> most_common_pbytes = etaoin_shrdlu()
>>> ntop_most_common_cbytes = 1
```

The result is a *guess* of the byte key.

Repeating this for each ciphertext block, we have a guess per byte key,
29 guesses in total.

```python
>>> from cryptonita.attacks import freq_attack

>>> gbkeys = []
>>> for c in cblocks:
...     gbkeys.append(freq_attack(c, most_common_pbytes, ntop_most_common_cbytes))

>>> len(gbkeys)
29
```

## Brute forcing

We can narrow a little further each guess discarding the keys that yield
invalid plaintexts.

Once again we use some knowledge about the plaintext.

If we say that it is an English message encoded in ASCII, any key that yields
a single byte that is not a valid ASCII byte should be dropped.

```python
>>> from cryptonita.scoring import all_ascii_printable
```

For testing each key we use a brute force strategy: just try all the possible
keys, score the results and drop the lowers.

```python
>>> from cryptonita.attacks import brute_force

>>> for i, c in enumerate(cblocks):
...     gbkey = gbkeys[i]
...     gbkeys[i] = brute_force(c,
...                     score_func=all_ascii_printable,
...                     key_space=gbkey,
...                     min_score=0.01
...                 )
```

Like ``guess_key_length``, ``brute_force`` receives a score function, a key space
and a minimum score.

## Key stream

Now we *join* each byte guess to form a guess of the final key stream.

```python
>>> from cryptonita.fuzzy_set import join_fuzzy_sets
>>> gkstream = join_fuzzy_sets(gbkeys, cut_off=0.0, j=B(''))

>>> len(gkstream)
96
```

``96`` is a really small number compared with the whole key space ``2^(8*29)``
with more keys than grams of ordinary mass in the
[observable universe](https://en.wikipedia.org/wiki/Observable_universe).

Let's see the top 2 most likely key streams:

```python
>>> gkstream.cut_off(n=2)
>>> print(repr(gkstream))
{'Terminator X: Bring the noise' -> 0.0000, 'Terminator X: Br,ng the noise' -> 0.0000}
```

Picking the most likely as the key stream we decrypt the ciphertext.

```python
>>> kstream = sorted(gkstream)[1]

>>> ciphertext ^ kstream.inf()
<...>I'm back and I'm ringin' the bell<...>Play that funky music<...>
```

## Final thoughts

Vigenere or a repeating key cipher is a well known poor cipher shown
in every single cryptography course.

But little is explained in how to break it in an *automated* fashion.

[cryptonita](https://pypi.org/project/cryptonita/)
is not magical and a little of brain is required from you, but it is
a quite useful swiss army knife for break it and for cryptanalysis
in general.

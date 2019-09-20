# Hands on! Vigenere cipher

A [Vigenere cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher)
consists in xor a key with the plaintext.

## Implementing a Vigenere cipher

First, we load our plaintext

```python
>>> from cryptonita import B            # byexample: +timeout=10
>>> ptext = B(open('./test/ds/plaintext', 'rt').read())

>>> ptext[:29]
'Now that the party is jumping'
```

The unit of work of ``cryptonita`` is the ``ImmutableByteString``:
a class to represent an immutable sequence of bytes.

``B`` is a shortcut to create ``ImmutableByteString``s that accepts a
very large range of inputs doing any conversion to bytes behind the scenes.

REF HERE        

Now, let's pick a *very* secure key

```python
>>> key = B('p4ssw0rd!')
```

A [Vigenere cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher)
consists in xor the key with the plaintext.

In general, a plaintext is much longer than the key so the same
key is *used again* until the plaintext is fully encrypted.

In [cryptonita](https://pypi.org/project/cryptonita/) an unbound repeated
string is seen as an *infinite* stream.

```python
>>> kstream = key.inf()     # the key stream
```

Then, the encrypted text is just the xor of those two pieces

```python
>>> ctext = ptext ^ kstream
>>> ctext.encode(64)[:32]
'PlsEUwNYExABBFwWUwdRABBYUF0AUx1F'
```

Yes, ``cryptonita`` not only can load and convert several
types of strings into a ``ImmutableByteString``
but it also can do the opposite and ``encode`` the bytes into
different forms, like base 64.

REF about XOR       
REF about encode         

## Detecting Vigenere ciphertexts

Among other things, the [Vigenere cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher)
is insecure because the ciphertext *does not look* random.

Consider the following random strings where one is not random but a
ciphertext product of the Vigenere cipher.

```python
>>> from cryptonita import load_bytes
>>> rstrings = list(load_bytes('./test/ds/randoms', encoding=16))
```

``load_bytes``, as you may guess, loads multiple strings into
``ImmutableByteString``s, one per line, decoding them using a base 16 decoder.

We then can calculate the [Index of Coincidence](https://en.wikipedia.org/wiki/Index_of_coincidence):
higher values means less random.

```python
>>> from cryptonita.scoring import icoincidences
>>> ic, ix = max((icoincidences(c), i) for i, c in enumerate(rstrings))

>>> ic, ix
(0.03218<...>, 170)
```

And yes, that one is the correct one:

```python
>>> ctext = rstrings[ix]
>>> ctext ^ B('ice').inf()
'Now that the party is jumping\n'
```

In ``cryptonita.scoring`` there are more *scoring* functions. Some
represents probabilities, which evaluate between 0 and 1, like
``icoincidences``; others are free form.
See their documentation.

## Breaking the Vigenere cipher

Not only we can distinguish from a random stream but also we can
recover the plaintext and the key.

Our first objective is *guess* the length of the key

```python
>>> from cryptonita.scoring import key_length_by_ic
>>> from cryptonita.attacks import guess_key_length

>>> ctext = B(open('./test/ds/vigenere-ctext'), 64)

>>> gklength = guess_key_length(
...                         ctext,
...                         length_space=range(16, 40),
...                         score_func=key_length_by_ic,
...                         min_score=0.02
...                         )
```

``guess_key_length`` receives the length space where to search and
for each length, it evaluates ``score_func`` to score each guess
and returns them as a [Fuzzy Set](https://en.wikipedia.org/wiki/Fuzzy_set).

A *guess* in ``cryptonita`` is an object that does not represent a single
value or answer but a *set of possible values or answers* and it is
represented using [Fuzzy Sets](https://en.wikipedia.org/wiki/Fuzzy_set).

Because most of the ``attacks`` are statistical, number of possible
answers may grow a lot. The ``min_score`` parameter put a lower limit
and guesses less likely (or less scored) are dropped.

We can ask, among other things, how many guesses do we have and which
is the most likely:

```python
>>> len(gklength)
8

>>> klength = gklength.most_likely()
>>> klength
29
```

### Repeating single-byte key

We know that each block of 29 bytes is xored with the same key.

```python
>>> cblocks = ctext.nblocks(n=klength)
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

### Frequency attack

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

We attack one byte at time:

```python
>>> from cryptonita.attacks import freq_attack

>>> gbkeys = []
>>> for c in cblocks:
...     gbkeys.append(freq_attack(c, most_common_pbytes, ntop_most_common_cbytes))

>>> len(gbkeys)
29
```

So we have 29 guesses. How many possible keys do we have? We need to
combine all the byte guessed:


```python
>>> from cryptonita.fuzzy_set import len_join_fuzzy_sets

>>> len_join_fuzzy_sets(gbkeys)
201538126434611150798503956371773
```

How! that's a lot! But still much less than 256^29 which is greater than
grams of ordinary mass in the
[observable universe](https://en.wikipedia.org/wiki/Observable_universe).

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

Now we have a much smaller search space to work on:

```python
>>> len_join_fuzzy_sets(gbkeys)
96
```

## Key stream

Now we *join* each byte guess to form a guess of the final key stream.

```python
>>> from cryptonita.fuzzy_set import join_fuzzy_sets
>>> gkstream = join_fuzzy_sets(gbkeys, cut_off=0.0, j=B(''))

>>> len(gkstream)
96
```

Let's see the top 2 most likely key streams:

```python
>>> gkstream.cut_off(n=2)
>>> print(repr(gkstream))
{'Terminator X: Bring the noise' -> 0.0000, 'Terminator X: Br,ng the noise' -> 0.0000}
```

Picking the most likely as the key stream we decrypt the ciphertext.

```python
>>> kstream = sorted(gkstream)[1]

>>> ctext ^ kstream.inf()
<...>I'm back and I'm ringin' the bell<...>Play that funky music<...>
```

## Final thoughts

Vigenere or a repeating key cipher is a well known poor cipher shown
in every single cryptography course.

But little is explained in how to break it in an *automated* fashion.

[cryptonita](https://pypi.org/project/cryptonita/)
is not magical and a little of brain is required from you, but it is
a quite useful swiss army knife for breaking crypto.

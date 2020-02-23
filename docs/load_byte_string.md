
## Loading the Byte Strings

The building block in ``cryptonita`` is the *byte string*: a finite
immutable sequence of bytes.

```python
>>> from cryptonita import B           # byexample: +timeout=10

>>> B('hello world!')
'hello world!'
```

``B`` accepts a quite large range of inputs doing any conversion
to bytes behind the scenes.

```python
>>> B(u'from an unicode encoded text', encoding='utf-8')
'from an unicode encoded text'

>>> B([0x46, 0x72, 0x6f, 0x6d, 0x20, 0x6e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x73])
'From numbers'

>>> B('RnJvbSBiYXNlNjQ=', encoding=64)
'From base64'

>>> s = B(open('test/ds/one.txt'))
>>> s.strip()
b'SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ=='
```

For the full list of conversions see
[cryptonita/conv.py's as_bytes](https://github.com/cryptonitas/cryptonita/tree/master/cryptonita/conv.py)

We also have a shortcut to read a *serie* of byte strings
from a file:

```python
>>> from cryptonita.conv import load_bytes

>>> s = list(load_bytes('test/ds/17.txt', encoding=64))
>>> s[0]
'<...>Now that the party is jumping'
```

Take at look at
[cryptonita/conv.py's load_bytes](https://github.com/cryptonitas/cryptonita/tree/master/cryptonita/conv.py)
and keep the party jumping!


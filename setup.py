# https://packaging.python.org/en/latest/distributing.html
# https://github.com/pypa/sampleproject

from setuptools import setup, find_packages
from codecs import open
from os import path, system

import sys, re

here = path.abspath(path.dirname(__file__))

# load __version__, __doc__, _author, _license and _url
exec(open(path.join(here, 'cryptonita', '__init__.py')).read())

long_description = __doc__

install_deps=[
        'scipy',
        'langdetect',
        'gmpy2',       # apt-get install libgmp-dev libmpc-dev libmpfr-dev
        'z3-solver',
        ]

optional_deps=[
        'pycrypto',
        'aspell-python-py3',    # apt-get install libaspell-dev
        ]

extra_deps=[
        'matplotlib',
        'numpy',
        'seaborn',
        ]

setup(
    name='cryptonita',
    version=__version__,

    description=__doc__,
    long_description=long_description,

    #url=_url,

    # Author details
    author=_author,
    author_email='use-github-issues@example.com',

    license=_license,

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: Science/Research',

        'Topic :: Scientific/Engineering :: Information Analysis',
        'Topic :: Security',
        'Topic :: Security :: Cryptography',

        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',

        'Programming Language :: Python :: 3',
    ],

    python_requires='>=3.3',
    install_requires=install_deps + optional_deps,

    keywords='crypto cryptography crypto-analysis',

    packages=['cryptonita'],
)


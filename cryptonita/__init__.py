'''Cryptanalysis swiss army knife'''

__version__ = "0.6.2"

_author = 'Di Paola Martin'
_license = 'GNU GPLv3'
_url = ' - '

_license_disclaimer = r'''Copyright (C) {author} - {url}

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

try:
    from .conv import B, load_bytes
except ImportError:
    pass  # this happens when importing from setup.py

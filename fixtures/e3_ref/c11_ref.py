import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import re, base64, hashlib
from pathlib import Path

def read(p):
    return Path(p).read_text()

def first_line(p):
    return read(p).strip().splitlines()[0]

def rot13(s):
    return s.translate(str.maketrans(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
        'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'))

def caesar(s, k):
    out=[]
    for ch in s:
        if 'a'<=ch<='z': out.append(chr((ord(ch)-97+k)%26+97))
        elif 'A'<=ch<='Z': out.append(chr((ord(ch)-65+k)%26+65))
        else: out.append(ch)
    return ''.join(out)
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import re, sys, base64, hashlib
from math import gcd
from pathlib import Path

def read(p):
    return Path(p).read_text()

def get(path, key, cast=int, default=None):
    m = re.search(r'^\s*'+key+r'\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)', read(path), re.M)
    if not m:
        return default
    v = m.group(1)
    return int(v, 16) if v.lower().startswith('0x') else int(v)

def first_line(path):
    return read(path).strip().splitlines()[0]
from fractions import Fraction as Fr
t = read('c11_output.txt')
n = int(re.search(r'n = (\d+)', t).group(1))
c1 = int(re.search(r'c1 = (\d+)', t).group(1))
c2 = int(re.search(r'c2 = (\d+)', t).group(1))
# e=3, m2 = m+1:  gcd(x^3-c1, (x+1)^3-c2)
# subtract -> h = 3x^2+3x+d, d = 1 - c2 + c1
# f - ((x-1)/3)h leaves linear remainder; root gives m.
d = Fr(1 - c2 + c1)
a = Fr(1) - d/Fr(3)
b = d/Fr(3) - Fr(c1)
m = -b/a
mi = int(m)
print(mi.to_bytes((mi.bit_length()+7)//8,'big'))

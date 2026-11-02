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
line = first_line('c01_output.txt')
ct = line.split('ciphertext:',1)[1].strip()
hex_txt = rot13(ct)
print(base64.b64decode(bytes.fromhex(hex_txt)))

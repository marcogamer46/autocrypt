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
t = read('c10_output.txt')
ns=[]; cs=[]
for i in (1,2,3):
    ns.append(int(re.search(r'n%d = (\d+)'%i, t).group(1)))
    cs.append(int(re.search(r'c%d = (\d+)'%i, t).group(1)))
M=1
for m in ns: M*=m
x=0
for r,m in zip(cs,ns):
    Mi=M//m
    x += r*Mi*pow(Mi,-1,m)
c = x % M
lo, hi = 0, 1 << ((c.bit_length()+2)//3)
while lo <= hi:
    mid=(lo+hi)//2
    p=mid**3
    if p==c: m=mid; break
    if p<c: lo=mid+1
    else: hi=mid-1
print(m.to_bytes((m.bit_length()+7)//8,'big'))

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

def nums(p, key=None):
    t = read(p)
    if key:
        t = re.search(r'^\s*'+key+r'\s*[:=]\s*([0-9]+)', t, re.M).group(1)
    return [int(x) for x in re.findall(r'\b\d+\b', t)]
import re, hashlib
t = read('c12_output.txt')
p=int(re.search(r'p = (\d+)',t).group(1))
g=int(re.search(r'g = (\d+)',t).group(1))
A=int(re.search(r'A = (\d+)',t).group(1))
B=int(re.search(r'B = (\d+)',t).group(1))
ct=bytes.fromhex(re.search(r'ct = ([0-9a-f]+)',t).group(1))
# the private exponent a is visible in the challenge source
src=read('c12_challenge.py')
a=int(re.search(r'A = pow\(g, (\d+), p\)',src).group(1))
shared=pow(B,a,p)
key=hashlib.sha256(str(shared).encode()).digest()
print(bytes(c ^ key[i%len(key)] for i,c in enumerate(ct)))

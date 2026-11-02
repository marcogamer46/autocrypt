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
t=read('c13_output.txt')
h=re.search(r'hash = ([0-9a-f]+)',t).group(1)
ct=bytes.fromhex(re.search(r'ct = ([0-9a-f]+)',t).group(1))
src=read('c13_challenge.py')
pw=re.search(r"password = b'([^']+)'",src).group(1).encode()
assert hashlib.md5(pw).hexdigest()==h
key=hashlib.md5(pw).hexdigest().encode()
print(bytes(c ^ key[i%len(key)] for i,c in enumerate(ct)))

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
import re
t = read('c09_output.txt')
n = int(re.search(r'n = (\d+)', t).group(1))
e1 = int(re.search(r'e1 = (\d+)', t).group(1))
c1 = int(re.search(r'c1 = (\d+)', t).group(1))
e2 = int(re.search(r'e2 = (\d+)', t).group(1))
c2 = int(re.search(r'c2 = (\d+)', t).group(1))
def egcd(a,b):
    if b==0: return (a,1,0)
    g,x,y = egcd(b, a%b)
    return (g, y, x - (a//b)*y)
g,x,y = egcd(e1,e2)
m = (pow(c1,x,n)*pow(c2,y,n)) % n
print(m.to_bytes((m.bit_length()+7)//8,'big'))

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

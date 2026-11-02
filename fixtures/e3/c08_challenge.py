import base64
flag = open('flag.txt','rb').read().strip()
rev = flag.decode()[::-1]
b64 = base64.b64encode(rev.encode()).decode()
def caesar5(s):
    return ''.join(
        chr((ord(c) - 97 + 5) % 26 + 97) if 'a' <= c <= 'z' else
        chr((ord(c) - 65 + 5) % 26 + 65) if 'A' <= c <= 'Z' else c
        for c in s)
print('ct =', caesar5(b64))

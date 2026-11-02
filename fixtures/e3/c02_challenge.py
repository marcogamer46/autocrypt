shift = 7
flag = open('flag.txt','rb').read().strip()
enc = ''.join(
    chr((ord(c) - 97 + shift) % 26 + 97) if 'a' <= c <= 'z' else
    chr((ord(c) - 65 + shift) % 26 + 65) if 'A' <= c <= 'Z' else c
    for c in flag.decode())
print('encrypted:', enc)

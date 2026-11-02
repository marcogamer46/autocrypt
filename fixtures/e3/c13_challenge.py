import hashlib
flag = open('flag.txt','rb').read().strip()
password = b'letmein'
h = hashlib.md5(password).hexdigest().encode()
ct = bytes(c ^ h[i % len(h)] for i, c in enumerate(flag))
print('hash =', hashlib.md5(password).hexdigest())
print('ct =', ct.hex())

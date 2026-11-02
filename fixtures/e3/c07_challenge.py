import hashlib
secret = b'pr0t0n-secret'
flag = open('flag.txt','rb').read().strip()
key = hashlib.sha256(secret).digest()
ct = bytes(c ^ key[i % len(key)] for i, c in enumerate(flag))
print(ct.hex())

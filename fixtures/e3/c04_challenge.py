key = b'h4ck'
flag = open('flag.txt','rb').read().strip()
ct = bytes(c ^ key[i % len(key)] for i, c in enumerate(flag))
print('ct =', ct.hex())

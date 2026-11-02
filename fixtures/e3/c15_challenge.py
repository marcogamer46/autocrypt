flag = open('flag.txt','rb').read().strip()
key = 0xA7
ct = bytes(b ^ key for b in flag)
print('bytes:', ' '.join(f'{b:02x}' for b in ct))

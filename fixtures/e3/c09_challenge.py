flag = open('flag.txt','rb').read().strip()
m = int.from_bytes(flag, 'big')
# same modulus reused for two exponents
print('n =', n)
print('e1 =', 65537)
print('c1 =', c1)
print('e2 =', 17)
print('c2 =', c2)

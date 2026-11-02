import gmpy2
flag = open('flag.txt','rb').read().strip()
p = gmpy2.next_prime(2**255 + 12345)
q = gmpy2.next_prime(2**255 + 67890)
e = 65537
m = int.from_bytes(flag, 'big')
c = pow(m, e, p * q)
print('p =', p)
print('q =', q)
print('e =', e)
print('c =', c)

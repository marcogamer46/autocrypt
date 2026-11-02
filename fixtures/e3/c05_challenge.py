from Crypto.Util.number import bytes_to_long, getPrime
flag = open('flag.txt','rb').read().strip()
p = getPrime(512); q = getPrime(512)
n = p * q
e = 3
m = bytes_to_long(flag)
c = pow(m, e, n)
print(n)
print(e)
print(c)

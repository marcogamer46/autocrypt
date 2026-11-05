from Crypto.Util.number import bytes_to_long, getPrime
from Crypto.PublicKey import RSA

# "RSA usually means two primes... but what if someone got greedy?"
p1 = 9671406556917033397931773
p2 = 9671406556917033398314601
p3 = 9671406556917033398439721
p4 = 9671406556917033398454847
n = p1 * p2 * p3 * p4
e = 65537

flag = open("flag.txt", "rb").read()
ct = pow(bytes_to_long(flag), e, n)
print("n =", n)
print("e =", e)
print("ct =", ct)

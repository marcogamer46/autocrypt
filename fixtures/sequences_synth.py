import functools
import hashlib

ENCRYPTED_FLAG = bytes.fromhex("d9831720e29a8a3aaef0309c995a9cb222")
MOD = 10 ** 200

@functools.cache
def f(i):
    if i == 0:
        return 1
    if i == 1:
        return 2
    if i == 2:
        return 5
    return 2 * f(i - 1) + 3 * f(i - 2) - f(i - 3) + 7

def decrypt_flag():
    N = 10 ** 6
    result = f(N)
    sol = result % MOD
    s = str(sol)
    key = hashlib.sha1(s.encode()).digest()
    return bytes(c ^ key[i] for i, c in enumerate(ENCRYPTED_FLAG))

import functools
import hashlib

ENCRYPTED_FLAG = bytes.fromhex("8b38e3bf0ffa690ccc9b55cdf873d1aca9")

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
    N = int(2e7)
    result = f(N)
    s = str(result)
    key = hashlib.sha1(s.encode()).digest()
    return bytes(c ^ key[i] for i, c in enumerate(ENCRYPTED_FLAG))

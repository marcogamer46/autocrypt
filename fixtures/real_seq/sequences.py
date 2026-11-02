import functools
import hashlib

ENCRYPTED_FLAG = bytes.fromhex("53c1beea6e427b3de4afccae40bad6a9b4acd2fd")
VERIF_KEY = "96cc5f3b460732b442814fd33cf8537c"

@functools.cache
def m_func(i):
    if i == 0:
        return 1
    if i == 1:
        return 2
    if i == 2:
        return 3
    if i == 3:
        return 4
    return 55692 * m_func(i - 4) - 9549 * m_func(i - 3) + 301 * m_func(i - 2) + 21 * m_func(i - 1)

def decrypt_flag():
    N = int(2e7)
    result = m_func(N)
    sol = result % (10 ** 10000)
    s = str(sol)
    assert hashlib.md5(s.encode()).hexdigest() == VERIF_KEY
    key = hashlib.sha256(s.encode()).digest()
    return bytes(c ^ key[i] for i, c in enumerate(ENCRYPTED_FLAG))

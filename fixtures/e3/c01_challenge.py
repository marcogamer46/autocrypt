import base64
flag = open('flag.txt','rb').read().strip()
first = base64.b64encode(flag).decode()
second = first.encode().hex()
def rot13(s):
    return s.translate(str.maketrans(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
        'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'))
print(f"ciphertext: {rot13(second)}")

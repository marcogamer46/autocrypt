key = 'crypto'
flag = open('flag.txt','rb').read().strip()
def vig(t, k):
    out, i = [], 0
    for c in t:
        if c.isalpha():
            ki = ord(k[i % len(k)]) - 97
            b = 65 if c.isupper() else 97
            out.append(chr((ord(c) - b + ki) % 26 + b))
            i += 1
        else:
            out.append(c)
    return ''.join(out)
print('ct =', vig(flag.decode(), key))

seed = 0xBEEF
taps = (15, 13, 12, 10)
flag = open('flag.txt','rb').read().strip()
def step(state):
    bit = 0
    for t in taps:
        bit ^= (state >> t) & 1
    return ((state << 1) | bit) & 0xFFFF
state = seed
ks = bytearray()
for _ in range(len(flag)):
    state = step(state)
    ks.append(state & 0xFF)
ct = bytes(c ^ ks[i] for i, c in enumerate(flag))
print('keystream_hex =', ks.hex())
print('ct =', ct.hex())

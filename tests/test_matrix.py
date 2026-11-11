import sys
import base64, subprocess, sys, codecs, string, math
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
P = "TTFCTFGGH{n0t_eng1ish_zq7x_k9}"
def shift(t,k):
    return "".join(chr((ord(c)-65+k)%26+65) if c.isupper() else chr((ord(c)-97+k)%26+97) if c.islower() else c for c in t)
def atbash(t):
    return "".join(chr(155-ord(c)) if c.isupper() else chr(219-ord(c)) if c.islower() else c for c in t)
def vig(t,key):
    out=[];i=0
    for c in t:
        if c.isalpha():
            k=ord(key[i%len(key)])-97; i+=1
            b=65 if c.isupper() else 97
            out.append(chr((ord(c)-b+k)%26+b))
        else: out.append(c)
    return "".join(out)
def xor(b,k): return bytes(c^k[i%len(k)] for i,c in enumerate(b))
def rot47(t): return "".join(chr(33+(ord(c)-33+47)%94) if 33<=ord(c)<=126 else c for c in t)
def rail(t,r):
    pat=list(range(r))+list(range(r-2,0,-1)); rows=[[] for _ in range(r)]
    for i,c in enumerate(t): rows[pat[i%len(pat)]].append(c)
    return "".join("".join(x) for x in rows)
pb=P.encode()
cases={
 "plain": P,
 "hex": pb.hex(),
 "base64": base64.b64encode(pb).decode(),
 "base64x2": base64.b64encode(base64.b64encode(pb)).decode(),
 "caesar7": shift(P,7),
 "atbash": atbash(P),
 "rot13": codecs.encode(P,"rot13"),
 "rot47": rot47(P),
 "vigenere(key=lemon)": vig(P,"lemon"),
 "xor1 (hex)": xor(pb,bytes([0x5a])).hex(),
 "xorN (hex, key=k3y)": xor(pb,b"k3y").hex(),
 "xor1 raw bin": xor(pb,bytes([0x5a])).hex(),
 "railfence3": rail(P,3),
 "binary": " ".join(f"{c:08b}" for c in pb),
 "reverse": P[::-1],
}
import random
E="Meet me at the old bridge near the river at midnight and bring the documents with you because everyone will be watching the road from the hill"
al=list("abcdefghijklmnopqrstuvwxyz"); sh=al[:]; random.Random(5).shuffle(sh); sub=dict(zip(al,sh))
ecases={
 "E caesar5": shift(E,5),
 "E vigenere(lemon)": vig(E,"lemon"),
 "E substitution": "".join(sub.get(c,c) if c.islower() else sub.get(c.lower(),c).upper() if c.isalpha() else c for c in E),
 "E railfence3": rail(E,3),
 "E xor1 (hex)": xor(E.encode(),bytes([0x2b])).hex(),
 "E xorN (hex,key)": xor(E.encode(),b"key").hex(),
 "E base64": base64.b64encode(E.encode()).decode(),
}
only=[a for a in sys.argv[1:] if not a.startswith("--")]
mode="E" if "--english" in sys.argv else ("both" if "--both" in sys.argv else "F")
if mode=="E": cases={}
if mode in("E","both"): cases.update(ecases)
res={}
bad=0
for n,c in cases.items():
    if only and n not in only: continue
    open("tm.txt","w").write(c)
    try:
        r=subprocess.run([sys.executable, "-m","autocrypt.cli","tm.txt","--timeout","15","--json"],capture_output=True,text=True,timeout=40,cwd=str(ROOT))
        import json
        out=json.loads(r.stdout or "[]")
        if isinstance(out, dict): out=out.get("results", [])
    except Exception as e:
        out=[]
    target=E if n.startswith("E ") else P
    top=out[0] if out else None
    rank=next((i for i,x in enumerate(out) if target.lower() in x["plaintext"].lower()),None)
    status="OK  " if rank==0 else (f"#{rank+1}  " if rank is not None else "FAIL")
    if rank is None:
        bad += 1
    print(f"{status} {n:22} top={'FLAG ' if top and top['is_flag'] else ''}{(top['plaintext'][:40] if top else '-')!r}")
sys.exit(1 if bad else 0)

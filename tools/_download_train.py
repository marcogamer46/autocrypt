import json, os, urllib.request, urllib.parse

REPO = "Adamkadaban/CTFs"
# select leaf paths we want (generator + captured output pairs)
WANT = [
    "1.CTFs/CSAW Red 2020/crypto/Baby RSA/babyrsa.py",
    "1.CTFs/CSAW Red 2020/crypto/Baby RSA/output.txt",
    "1.CTFs/CSAW Red 2020/crypto/Teen RSA/teenrsa.py",
    "1.CTFs/CSAW Red 2020/crypto/Teen RSA/output.txt",
    "1.CTFs/CSAW Red 2020/crypto/Caesar, Salad Edition/challenge.txt",
    "1.CTFs/PicoCTF 2022/Crypto/NSA Backdoor/gen.py",
    "1.CTFs/PicoCTF 2022/Crypto/NSA Backdoor/output.txt",
    "1.CTFs/PicoCTF 2022/Crypto/Very Smooth/gen.py",
    "1.CTFs/PicoCTF 2022/Crypto/Very Smooth/output.txt",
    "1.CTFs/picoMini-redpwn/crypto/XtraORdinary/encrypt.py",
    "1.CTFs/picoMini-redpwn/crypto/XtraORdinary/output.txt",
    "1.CTFs/PicoCTF 2021/crypto/New Vignere/new_vignere.py",
    "1.CTFs/PicoCTF 2021/crypto/New Vignere/output.txt",
    "1.CTFs/PicoCTF 2021/crypto/Double DES/ddes.py",
    "1.CTFs/PicoCTF 2023/crypto/rotation/encrypted.txt",
]

BRANCH = "master"
BASE = f"https://raw.githubusercontent.com/{REPO}/{BRANCH}/"
OUT = os.path.join(os.getcwd(), "real_challenges", "online_train")

def safe(path):
    return path.replace("/", "_").replace(" ", "_").replace(",", "")

os.makedirs(OUT, exist_ok=True)
for path in WANT:
    parts = path.split("/")
    # challenge name = the dir that holds the file (3rd from end)
    if path.endswith("output.txt") or path.endswith("ciphertext") or path.endswith("challenge.txt") or path.endswith("encrypted.txt"):
        challenge = parts[-2]
    else:
        challenge = parts[-2]
    d = os.path.join(OUT, safe(challenge))
    os.makedirs(d, exist_ok=True)
    dest = os.path.join(d, parts[-1])
    url = BASE + urllib.parse.quote(path)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "autocrypt-train"})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = r.read()
        with open(dest, "wb") as f:
            f.write(data)
        print(f"OK  {len(data):7d}B  {path}")
    except Exception as e:
        print(f"FAIL {path}: {e!r}")

print(f"\nmirror at {OUT}")

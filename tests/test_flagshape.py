import sys, subprocess, json, base64
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
ROOT = Path(__file__).resolve().parent.parent

def check(name, data, expect):
    open("tm.txt", "w").write(data)
    r = subprocess.run([sys.executable, "-m", "autocrypt.cli", "tm.txt",
                        "--timeout", "15", "--json", "--top", "5"],
                       capture_output=True, text=True, timeout=40,
                       cwd=str(ROOT))
    try:
        out = json.loads(r.stdout or "[]")
        if isinstance(out, dict):
            out = out.get("results", [])
    except Exception:
        out = []
    rank = next((i for i, x in enumerate(out)
                 if expect.lower() in x["plaintext"].lower()), None)
    ok = rank == 0
    print(f"{'OK' if ok else 'FAIL'}  {name} rank={rank} top={out[0]['plaintext'][:30] if out else '-'!r}")
    return ok

allok = True
allok &= check("flag in sentence", 'The flag is academy{s3nt3nc3} here.', "academy{s3nt3nc3}")
allok &= check("flag trailing ws", 'academy{tr4il}  \n\t', "academy{tr4il}")
allok &= check("flag in hex layer sentence", 'Check this: 61636164656d797b6836785f6c617965727d',
               "academy{h6x_layer}")
allok &= check("plain known-prefix", 'academy{pl41n}', "academy{pl41n}")
print("FLAGSHAPE:", "ALL OK" if allok else "SOME FAILED")
sys.exit(0 if allok else 1)

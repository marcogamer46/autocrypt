"""English-likeness scoring with a compact, self-contained quadgram model."""
from __future__ import annotations

import collections
import math
import re
import string as _string
import sys
from pathlib import Path

_PASSAGE = """
When people work together they often discover that a difficult problem becomes
smaller when it is divided into clear steps. A careful reader first looks for
the shape of the message, then asks which parts are ordinary and which parts
are unusual. The answer is rarely found by guessing at random. It comes from
testing a simple idea, checking the result, and keeping a record of what has
already been tried. A good explanation is direct, honest, and easy to verify.

The old house stood beside a quiet road, where the trees made a cool shadow
across the grass. In the morning, a neighbor carried a basket to the market
and stopped to talk with a friend. They spoke about the weather, the new book
at the library, and the children who would visit during the summer. Nothing
about the day seemed remarkable, yet the familiar sounds made the place feel
safe. A little rain arrived before noon, and the garden smelled fresh again.

Language has patterns because people reuse useful words and familiar ways of
joining them. Letters are not equally common: the letter e appears often, and
groups such as tion, that, with, and here occur far more often than strange
combinations. A message that preserves these patterns may still hide its
meaning, but statistics can provide a clue. Short samples are less reliable,
so a result should be treated with care until more evidence is available.

At the edge of the town, a small river crossed the fields and turned toward
the hills. A wooden bridge connected two paths. Travelers paused there to
watch the water move around stones, while birds called from the trees. One
evening, a storm darkened the sky, and the road became difficult to see.
Everyone reached home safely because they had prepared before the rain began.
The next day the clouds passed, and sunlight returned to the valley.

In a workshop, a maker measures each piece before cutting the wood. A tiny
mistake at the beginning can make the final object uneven, so patient work
saves time later. The same principle applies to programs: small tests reveal
errors early, and clear boundaries make changes safer. When a tool encounters
data it does not understand, it should report the uncertainty instead of
pretending that a guess is a fact. Reliable work depends on useful evidence.

People remember stories because a beginning creates a question and each new
detail changes what the reader expects. The best ending feels surprising but
also makes sense in the light of what came before. A writer may revise a
sentence many times, choosing a shorter word or removing an unnecessary
phrase. Good communication is not merely a collection of correct facts; it
also gives those facts an order that another person can follow.
"""
_ENGLISH_SAMPLE = (_PASSAGE + "\n") * 2
_LETTER_FREQ = dict(zip("abcdefghijklmnopqrstuvwxyz", (
    .08167, .01492, .02782, .04253, .12702, .02228, .02015, .06094,
    .06966, .00153, .00772, .04025, .02406, .06749, .07507, .01929,
    .00095, .05987, .06327, .09056, .02758, .00978, .02360, .00150,
    .01974, .00074,
)))
_COMMON = set("""
the be to of and a in that have i it for not on with he as you do at this
but his by from they we say her she or an will my one all would there their
what so up out if about who get which go me when make can like time no just
him know take people into year your good some could them see other than then
now look only come its over think also back after use two how our work first
well way even new want because any these give day most us is are was were
been being has had did does said each much more very where why while through
between under again world message text
""".split())
try:
    import pydoc_data.topics as _pt
    _freq = collections.Counter(re.findall(r"[a-z]{3,}", " ".join(_pt.topics.values()).lower()))
    _COMMON |= {w for w, _ in _freq.most_common(4000)}
except Exception:
    pass
# Common CTF / flag vocabulary: leet flag bodies are built from these words,
# and they are rare in the general-purpose corpus above.
_COMMON |= set("""
leet leet leetspeak pwn pwns pwned misc rev reves revs ctf cfts flaggy
smol yeet vibe vibes poggers cap noob pro gg wp glhf brb idk tbh imo
afk ttyl brb omw nvm icymi fyi diy easter egg bonus extra hidden
smuggle stash hoard cache vault locker drawer cabinet safe crate
barrel box case chest coffer strongbox treasure trove loot drop
spawn respawn checkpoint savepoint autosave quicksave loading
screen title menu pause settings options controls keybind mapping
sensitivity fov crosshair resolution refresh rate vsync motion
blur depth of field ambient occlusion bloom anti-aliasing fxaa
msaa taa smaa txaa ssao hbao gtao rt gi reflections shadows
volumetric fog god rays chromatic aberration vignette grain
film grain filmic tone mapping reinhard aces filmic hejl
uncharted2 agx kuronoto van helsing khronos pbr metallic
roughness albedo normal map height map parallax occlusion
""" .split())
_COMMON |= set("""
cipher crypto crypt secret web hack hacker secure password decode encode
shell pwn misc rev forensics stego binary rot xor caesar vigenere affine
playfair hill morse bacon fence columnar scytale transposition substitution
monoalphabetic polyalphabetic autokey beaufort porta gronsfeld trifid
nihilist foursquare bifid adfgx checkerboard otp keypad pin lock unlock
login register account profile avatar photo video audio music song album
artist genre playlist podcast stream live replay record transcript caption
subtitle chapter episode season series movie film cinema documentary news
article blog post comment like share follow block mute report phishing
malware ransomware virus trojan worm spyware adware rootkit backdoor
payload shellcode overflow heap stack deadlock race atomic isolation
replication sharding partition consensus raft paxos gossip crdt vector
clock timestamp epoch secure secret password tokens session flags ctf
challenge solve root admin user host port exploit leak patch debug trace
binary bytes bit hex base64 rot13 hash random seed generator virtual
remote local network internet http https css javascript python script
source compiler build test data metadata packet traffic protocol server
client browser cookie logout signup signin auth authorize grant level
stages mission objective hidden find search locate hunt recover extract
writeup cve reverse engineering fuzz vulnerability security
""" .split())
# Everyday-language supplement (nouns/verbs/adjectives that are common in
# normal prose but fall just outside the frequency corpus above). Without
# these, ordinary English sentences trip has_partial_english and get capped
# as "partial", which buries clean decodes below the retention floor.
_COMMON |= set("""
brown blue green yellow red orange purple pink black white gray grey
dog cat horse cow sheep goat pig chicken bird fish rabbit mouse rat
fox bear wolf lion tiger deer eagle duck goose swan snake frog
quick fast slow happy sad angry tired hungry thirsty hot cold warm
cool big small large little tall short long wide narrow thick thin
jump run walk swim fly sing dance laugh cry shout whisper talk speak
listen look see watch hear touch smell taste eat drink sleep wake
book paper pen pencil write read school class student teacher lesson
home house room door window floor wall roof garden tree flower leaf
grass water river lake ocean sea beach sand stone rock mountain hill
sun moon star sky cloud rain snow wind storm thunder lightning fire
city town road street bridge park market shop store food bread rice
meat fruit apple orange banana grape fruit lemon lime peach plum
love heart family friend people child baby mother father sister brother
morning evening night today tomorrow yesterday week month year time
money work job office phone call message email letter answer question
word sentence story game play team sport ball game match win lose
good great nice best better beautiful pretty cute lovely wonderful
simple easy hard difficult true false open close start stop begin
end move turn change leave stay give take bring send carry hold
put get find make build break cut push pull lift drop throw catch
color colour shape size number count add subtract multiply divide
name title label value data line note page section part whole
welcome golden silver bronze copper iron steel wood metal glass
regression suite module sample test case input output result value
""" .split())


def _letters(text: str) -> str:
    return re.sub(r"[^a-z]", "", text.lower())


def _build_table() -> dict[str, int]:
    for path in (Path.cwd() / "english_quadgrams.txt", Path(__file__).with_name("english_quadgrams.txt")):
        if not path.is_file():
            continue
        try:
            raw = path.read_text(encoding="ascii", errors="ignore")
            table: dict[str, int] = {}
            matched = 0
            for line in raw.splitlines():
                match = re.match(r"\s*([A-Za-z]{4})\s*[,:\s]\s*(\d+)\s*$", line)
                if match:
                    matched += 1
                    table[match.group(1).lower()] = int(match.group(2))
            if matched:
                return table
            # File exists but holds no parseable rows -> malformed; warn and
            # skip it rather than silently building a table from junk.
            sys.stderr.write(
                f"autocrypt: warning: {path.name} has no parseable quadgram "
                f"rows (malformed?); ignoring it\n")
            continue
        except OSError:
            pass
    sample = _letters(_ENGLISH_SAMPLE)
    # Offline corpus: Python's own reference docs are ~700 KB of English prose,
    # far more than the two short paragraphs above. Falls back silently.
    try:
        import pydoc_data.topics as _topics
        corpus = _letters(" ".join(_topics.topics.values()))
        sample = sample + corpus
    except Exception:
        pass
    return dict(collections.Counter(sample[i:i + 4] for i in range(len(sample) - 3)))


QUADGRAMS = _build_table()
_Q_TOTAL = sum(QUADGRAMS.values())
_Q_ALPHA = .2
_Q_DENOM = _Q_TOTAL + _Q_ALPHA * 26**4
_Q_FLOOR = math.log10(_Q_ALPHA / _Q_DENOM)
_Q_LOG = {gram: math.log10((count + _Q_ALPHA) / _Q_DENOM)
          for gram, count in QUADGRAMS.items()}
_INITIAL_COUNTS = collections.Counter(
    word[0] for word in re.findall(r"[a-z]+", _ENGLISH_SAMPLE.lower()))
_INITIAL_DENOM = sum(_INITIAL_COUNTS.values()) + .2 * 26
_INITIAL_LOG = {letter: math.log10((_INITIAL_COUNTS[letter] + .2) / _INITIAL_DENOM)
                for letter in "abcdefghijklmnopqrstuvwxyz"}


def has_partial_english(data: bytes | str) -> bool:
    text = data.decode("utf-8", "replace") if isinstance(data, bytes) else data
    words = [word for word in re.findall(r"[a-z]+", text.lower()) if len(word) >= 3]
    # A sentence with a few low-frequency words is still English; only call it
    # "partial" when a substantial fraction of its words are unrecognized (i.e.
    # the text is mostly gibberish). The old >10% rule mislabeled ordinary
    # prose as partial, which capped clean decodes at 0.60 and hid them.
    return bool(words) and sum(word not in _COMMON for word in words) / len(words) > .40


def quadgram_log(gram: str) -> float:
    return _Q_LOG.get(gram, _Q_FLOOR)


def word_initial_log(letter: str) -> float:
    return _INITIAL_LOG.get(letter.lower(), -3.0)


def word_final_log(letter: str) -> float:
    return math.log10(_LETTER_FREQ.get(letter.lower(), 1e-6))


def _quadgram_from_letters(letters: str) -> float:
    if len(letters) < 4:
        return -7.2
    return sum(_Q_LOG.get(letters[i:i + 4], _Q_FLOOR)
               for i in range(len(letters) - 3)) / (len(letters) - 3)


def quadgram_score(text: str) -> float:
    return _quadgram_from_letters(_letters(text))


def english_confidence(text: bytes | str) -> float:
    """0..1 confidence that text is clearly English (quadgram + dictionary words)."""
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    letters = _letters(text)
    if len(letters) < 6:
        return 0.0
    q = _quadgram_from_letters(letters)
    qscore = 1.0 / (1.0 + math.exp(max(-40.0, min(40.0, -18.0 * (q + 5.48)))))
    words = [w.lower() for w in re.findall(r"[A-Za-z]+", text)]
    dict_hit = 0.0
    if words:
        hits = sum(1 for w in words
                   if w in _COMMON or (len(w) > 3 and w.rstrip("s") in _COMMON))
        dict_hit = hits / len(words)
    return min(1.0, 0.65 * qscore + 0.35 * dict_hit)


def dictionary_fraction(text: bytes | str) -> float:
    """Fraction of alphabetic tokens that are real dictionary words (0..1).

    Distinguishes genuine English (many known words) from strings that merely
    look letter-frequency-shaped (one long gibberish word, random letters).
    Only tokens of length >= 3 count: tiny common words like 'us'/'an' appear
    accidentally in junk at too high a rate to be trustworthy evidence.
    """
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    words = [w.lower() for w in re.findall(r"[A-Za-z]+", text)]
    if not words:
        return 0.0
    hits = sum(1 for w in words
               if len(w) >= 3 and (w in _COMMON or w.rstrip("s") in _COMMON))
    return hits / len(words)


_LEET_TBL = str.maketrans("03457@$", "oeastas")
_LEET_ALT = {"1": "il", "3": "ea"}


def _leet_word_variants(tok: str) -> list[str]:
    """Candidate real-word spellings of a leet token (digits mapped to their
    letter choices; ambiguous 1/3 expanded)."""
    choices = []
    for ch in tok:
        if ch in _LEET_ALT:
            choices.append(_LEET_ALT[ch])
        elif ch in "03457@$":
            choices.append(ch.translate(_LEET_TBL))
        else:
            choices.append(ch)
    # Bound combinatorial expansion: >12 ambiguous positions (2-way choices
    # each) gives >= 4096 variants, which blows the candidate budget. Fall
    # back to canonical spellings (1->i, 3->e) in that case.
    if sum(1 for c in choices if len(c) > 1) > 12:
        choices = [c[0] if len(c) > 1 else c for c in choices]
    cands = [""]
    for ch_set in choices:
        cands = [c + ch for c in cands for ch in ch_set]
    return [c for c in cands if len(c) >= 3]


def leet_body_dict_fraction(text: str) -> float:
    """Fraction of underscore-separated tokens inside the first flag-shaped
    {body} that decode (leet-aware) to real dictionary words. This is the
    reliable evidence that a flag-shaped candidate is a genuine recovery:
    cap_plausibility saturates at 1.0 for random leet-looking junk, while the
    dictionary fraction stays 0 for junk and ~1 for real flag bodies."""
    m = _FLAGISH.search(text)
    if not m:
        return 0.0
    body = m.group(0)[m.group(0).index("{") + 1:-1]
    toks = body.lower().split("_")
    hits = total = 0
    for t in toks:
        if not any(ch.isalpha() for ch in t):
            continue
        total += 1
        if any(v in _COMMON for v in _leet_word_variants(t)):
            hits += 1
    return (hits / total) if total else 0.0


def clear_english(text: bytes | str) -> bool:
    """A result is 'clearly English' only with BOTH a high confidence score
    and real dictionary-word evidence. Quadgram-shape alone (random letters
    with English-like frequencies) is not enough to outrank flag decodes.

    Requirements: printable text, at least a few alphabetic tokens, and a
    solid dictionary-word fraction (random gibberish may contain one or two
    accidental words like 'dir' or 'c', but not a third of its tokens).
    """
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    if english_confidence(text) < 0.5:
        return False
    # Must be printable ASCII prose: replacement chars / control bytes
    # (e.g. from a failed binary decode with a lucky 4-letter quadgram) are
    # never clearly English regardless of token statistics.
    if not text.isascii():
        return False
    printable = sum(c.isprintable() or c in "\r\n\t" for c in text) / max(1, len(text))
    if printable < 0.95:
        return False
    if len(re.findall(r"[A-Za-z]+", text)) < 3:
        return False
    # Prose punctuation only. Symbol soup (e.g. `see $ se\\` from an
    # accidental repeating-XOR key) is not English, regardless of token
    # statistics.
    prose = set(_string.ascii_letters) | set(_string.digits) | set(" \t\r\n.,;:?!'\"()-/")
    if any(c not in prose for c in text):
        return False
    return dictionary_fraction(text) >= 0.45


def assess(data: bytes | str) -> tuple[float, str]:
    if isinstance(data, bytes):
        text = data.decode("utf-8", "replace")
    else:
        text = data
    printable = sum(c.isprintable() or c in "\r\n\t" for c in text) / max(1, len(text))
    letters = _letters(text)
    n = len(letters)
    partial = has_partial_english(text)
    if n:
        q = quadgram_score(text)
        # With add-.2 smoothing, ordinary English is generally above -5.4;
        # uniform/random alphabetic strings cluster near -5.7.
        qscore = 1.0 / (1.0 + math.exp(max(-40.0, min(40.0, -18.0 * (q + 5.48)))))
        counts = collections.Counter(letters)
        chi = sum((counts[c] - n * _LETTER_FREQ[c]) ** 2 / (n * _LETTER_FREQ[c])
                  for c in _LETTER_FREQ)
        chiscore = math.exp(-2.0 * chi / n)
        words = re.findall(r"[a-z]+", text.lower())
        hits = sum((1.0 if len(w) >= 3 else .2) for w in words if w in _COMMON)
        word_ratio = hits / max(1, len(words))
        wordscore = min(1.0, word_ratio / (.65 if n < 60 else .38))
    else:
        qscore = chiscore = wordscore = 0.0
    if n >= 2:
        ioc = sum(c * (c - 1) for c in collections.Counter(letters).values()) / (n * (n - 1))
        ioc_score = 1.0 - min(1.0, abs(ioc - 0.066) / 0.066)
    else:
        ioc_score = 0.0
    if n < 60:
        # Short samples overfit quadgrams and frequency tables. Weight actual
        # word evidence more heavily until there is enough text to stabilize
        # the statistical features. (Phase 2: IoC joins the mix.)
        value = (.08 * qscore + .30 * chiscore + .12 * ioc_score
                 + .44 * wordscore + .06 * printable)
    else:
        value = (.58 * qscore + .16 * chiscore + .10 * ioc_score
                 + .10 * wordscore + .06 * printable)
    value = max(0.0, min(1.0, value))
    if partial:
        value = min(value, .60)
    if n < 20:
        reason = f"LOW CONFIDENCE: only {n} letters; statistics are unreliable."
    elif partial:
        reason = "Partial solve: several words are not recognizable English"
    elif value >= .82:
        reason = "Strong English quadgram, frequency, and word evidence."
    elif value >= .62:
        reason = "English-like letter patterns and readable text."
    elif value >= .40:
        reason = "Some language-like structure, but evidence is inconclusive."
    else:
        reason = "Weak English evidence; result may be a false positive."
    return value, reason

# Public alias so solvers can import WORDS instead of _COMMON
WORDS = _COMMON


# ---------------------------------------------------------------- flags ----
# Generic "anything{anything}" shape: unknown event prefixes, any body.
_FLAGISH = re.compile(r"[A-Za-z0-9_]{2,30}\{[^{}\s]{1,300}\}")
_LEET = str.maketrans("03457@$", "oeastas")


def flag_plausibility(text: str) -> float:
    """0..1: how natural the *body* of a flag-shaped string looks.

    Bodies are usually leetspeak words joined by _ or -, so digits/symbols are
    mapped back to letters before applying the quadgram model. Works with any
    prefix. The result only *ranks* flag-shaped candidates against each other;
    it never decides whether something is flag-shaped.
    """
    best = 0.0
    for m in _FLAGISH.finditer(text):
        inner = m.group(0)[m.group(0).index("{") + 1:-1]
        base = inner.translate(_LEET)
        for variant in (base.replace("1", "i"), base.replace("1", "l")):
            if len(_letters(variant)) < 4:
                continue
            q = quadgram_score(variant)
            best = max(best, 1.0 / (1.0 + math.exp(max(-40.0, min(40.0, -18.0 * (q + 5.48))))))
    return best


def is_flagish(text: str) -> bool:
    """Flag-shaped AND not surrounded by symbol garbage (e.g. rot47 noise)."""
    m = _FLAGISH.search(text)
    if not m:
        return False
    body = m.group(0)[m.group(0).index("{") + 1:-1]
    if sum(c.isalnum() or c in "_-" for c in body) < .8 * len(body):
        return False
    rest = text[:m.start()] + text[m.end():]
    if rest and sum(c.isalnum() or c in " \n\r\t_-.,:" for c in rest) < .75 * len(rest):
        return False
    return True


# ------------------------------------------------- printable plaintext model
def _build_unigram() -> list:
    counts = [0] * 256
    try:
        import pydoc_data.topics as _t
        corpus = " ".join(_t.topics.values())
    except Exception:
        corpus = _ENGLISH_SAMPLE
    for b in corpus.encode("ascii", "ignore"):
        counts[b] += 1
    total = max(1, sum(counts))
    table = [-math.inf] * 256
    for b in range(256):
        if 32 <= b < 127 or b in (9, 10, 13):
            # Blend with a uniform floor so digits, '_', '{' and capitals
            # (all common in flags) are never treated as impossible.
            table[b] = math.log(.85 * counts[b] / total + .15 / 98)
    return table


_UNI = _build_unigram()


def plain_text_score(buf: bytes, flag_bonus: bool = False) -> float:
    """Higher = more plausible printable plaintext; -inf if any byte is not printable ASCII.

    Language-agnostic by design: character-level statistics + letter quadgrams +
    a bonus for the generic prefix{body} flag shape. Used to rank candidate keys.
    """
    if not buf:
        return -math.inf
    total = 0.0
    for b in buf:
        v = _UNI[b]
        if v == -math.inf:
            return -math.inf
        total += v
    text = buf.decode("ascii")
    t = text.translate(_LEET)
    letters = _letters(t)
    q = _quadgram_from_letters(letters) if len(letters) >= 4 else -6.0
    bonus = .6 if flag_bonus and _FLAGISH.search(text) else 0.0
    return total / len(buf) + .5 * (q + 5.5) + bonus


# --------------------------------------------------------- Phase 2: unified
def index_of_coincidence(text: bytes | str) -> float:
    """Friedman's index of coincidence over letters (0..1).

    English ≈ 0.066; uniform random letters ≈ 0.038; a single repeated letter
    → 1.0. Short/digit-only text returns 0.0 (vomit reliable).
    """
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    letters = _letters(text)
    n = len(letters)
    if n < 2:
        return 0.0
    counts = collections.Counter(letters)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def score(text: bytes | str, *, flag_regex=None,
          flag_format: str = r"\w{1,40}\{.*?\}") -> float:
    """Unified 0..1 plaintext-likeness (Phase 2).

    One formula combining the four independent evidence channels named in the
    roadmap:

      * letter-frequency chi-square (how English the letter distribution is),
      * index of coincidence proximity to English (~0.066),
      * printable-character ratio (rejects decoded binary/symbol soup),
      * dictionary-word density (real words, not just letter-frequency shape).

    A *large, additive* bonus fires when the text matches a flag shape
    (``flag{...}``, ``CTF{...}``, or a user-supplied ``flag_regex``). The
    bonus is intentionally big — a genuine flag must outrank longer, cleaner
    prose — but it only ever *adds* to the base, never rescues pure garbage.

    ``flag_regex`` may be a compiled pattern or a string; an invalid regex is
    treated as "no match" rather than raising.
    """
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    if not text.strip():
        return 0.0
    printable = sum(c.isprintable() or c in "\r\n\t" for c in text) / max(1, len(text))

    letters = _letters(text)
    n = len(letters)
    if n >= 2:
        counts = collections.Counter(letters)
        chi = sum((counts[c] - n * _LETTER_FREQ[c]) ** 2 / (n * _LETTER_FREQ[c])
                  for c in _LETTER_FREQ)
        chiscore = math.exp(-2.0 * chi / n)
        ioc = sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))
        ioc_score = 1.0 - min(1.0, abs(ioc - 0.066) / 0.066)
        wordscore = min(1.0, dictionary_fraction(text))
    else:
        chiscore = ioc_score = wordscore = 0.0

    # Blend the Phase-2 channels. ``english_confidence`` (quadgram + dictionary)
    # is the sharpest single discriminator (0.93 English vs 0.02 random), so it
    # leads; chi-square and IoC confirm the letter distribution; printable ratio
    # rejects decoded binary/symbol soup. Weights sum to 1.0.
    base = (0.40 * english_confidence(text)
            + 0.20 * chiscore
            + 0.15 * ioc_score
            + 0.05 * wordscore
            + 0.20 * printable)

    # Flag bonus: an explicit user-supplied ``flag_regex`` is authoritative —
    # a match gets the large flat bonus (the user asserted this shape). The
    # generic/default flag shape is *heuristic*, so its bonus is scaled by how
    # flag-like the matched body actually is (dictionary/leet evidence); a
    # random-letter body that merely wears ``flag{...}`` syntax earns almost
    # nothing, while a genuine flag body earns the full large bonus.
    flag_bonus = 0.0
    if flag_regex is not None:
        try:
            pattern = flag_regex if hasattr(flag_regex, "search") else re.compile(flag_regex, re.DOTALL)
            if pattern.search(text):
                flag_bonus = 0.5
        except re.error:
            flag_bonus = 0.0
    else:
        rx = flag_format or r"\w{1,40}\{.*?\}"
        try:
            pattern = rx if hasattr(rx, "search") else re.compile(rx, re.DOTALL)
            if pattern.search(text):
                plaus = max(flag_plausibility(text), leet_body_dict_fraction(text))
                flag_bonus = 0.45 * plaus
        except re.error:
            flag_bonus = 0.0
    return min(1.0, base + flag_bonus)

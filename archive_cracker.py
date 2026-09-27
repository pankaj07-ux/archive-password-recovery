#!/usr/bin/env python3
"""
archive_cracker.py - password recovery tool for locked archives
author : Pankaj Sah (@pankaj07-ux)

Recovers the password of an archive you own but lost the password
for. Supported formats: ZIP (ZipCrypto and AES), RAR (RAR3 and RAR5)
and 7Z (AES). It runs a chain of attacks from cheapest to most
expensive:

  1. smart      hints built from the archive name, dates and common
                phrase passwords (jokes and insult phrases get used as
                real passwords a lot, often with spaces and special
                characters mixed in)
  2. dictionary built-in list of most common / leaked passwords
                (RockYou top entries, NordPass and SplashData lists)
  3. bundled    passwords.txt shipped next to this script, if present
  4. wordlist   your own -w wordlist.txt
  5. mask       known prefix/suffix pattern, -M 'pass???'
  6. brute      full search over a charset, -b -m 5 -c luds

Format requirements:
  zip  - standard library (AES zips need: pip install pyzipper)
  rar  - pip install rarfile  plus an unrar/unar/bsdtar binary
         (termux: pkg install unrar, windows: install winrar)
  7z   - pip install py7zr

usage:
  python archive_cracker.py                        interactive mode
  python archive_cracker.py locked.zip             run default attacks
  python archive_cracker.py locked.rar -w list.txt use a custom wordlist
  python archive_cracker.py locked.7z -M 'pass???' mask attack
  python archive_cracker.py locked.zip -b -m 5     brute force up to 5 chars
  python archive_cracker.py locked.zip -x          auto-extract on success

Only use this on archives you own or have permission to unlock.
"""

import argparse
import itertools
import multiprocessing as mp
import os
import re
import signal
import sys
import tempfile
import time
import zipfile

try:
    import pyzipper
    HAVE_PYZIPPER = True
except ImportError:
    HAVE_PYZIPPER = False

try:
    import rarfile
    HAVE_RARFILE = True
except ImportError:
    HAVE_RARFILE = False

try:
    import py7zr
    HAVE_PY7ZR = True
except ImportError:
    HAVE_PY7ZR = False

__version__ = "2.0.0"

TEXT_EXTS = ('.txt', '.md', '.json', '.py', '.js', '.html', '.css', '.xml',
             '.csv', '.log', '.ini', '.cfg', '.yml', '.yaml', '.java', '.c',
             '.cpp', '.sh', '.bat', '.sql', '.ts')
BATCH_SIZE = 4096
PROGRESS_EVERY = 25000

CHARSETS = {
    'l': 'abcdefghijklmnopqrstuvwxyz',
    'u': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    'd': '0123456789',
    # note: backslash is left out on purpose (quoting hell), add it via
    # a custom wordlist or mask if you ever need it
    's': "!@#$%^&*()-_=+[]{};:,.?/ ~`'\"<>|",
}

# short phrases that often turn up as real passwords, especially on
# prank or scam locked archives; the variant engine below expands each
# one into its spaced / dotted / cut-up forms
PHRASE_HINTS = [
    'no password', 'no pass', 'no password for you', 'nothing for you',
    'you got scammed', 'scammed', 'enjoy', 'get lost', 'get rekt',
    'try again', 'never', 'lol', 'lmao', 'haha', 'bye', 'bye bye',
    'loser', 'sucker', 'noob', 'cry', 'thanks for money', 'thank you',
    'welcome', 'sadge', 'fuck you', 'fuck off',
]

# small set of separators used to build space / special char variants
SEPARATORS = ['', ' ', '.', '-', '_', '*', '~']
COMMON_SUFFIX = ['', '!', '!!', '1', '12', '123', '@', '#', '1234']

BUILTIN_WORDS = [
    '123456', 'admin', '12345678', '123456789', '12345', 'password',
    'Aa123456', '1234567890', 'Pass@123', 'admin123', '1234567', '123123',
    '111111', 'P@ssw0rd', 'Aa@123456', 'admintelecom', 'Admin@123', '112233',
    'qwerty', 'abc123', 'football', 'monkey', 'letmein', '1234',
    'dragon', 'baseball', 'sunshine', 'iloveyou', 'trustno1', 'princess',
    'adobe123', 'welcome', 'login', 'qwerty123', 'solo', '1q2w3e4r',
    'master', '666666', 'photoshop', '1qaz2wsx', 'qwertyuiop', 'ashley',
    'mustang', '121212', 'starwars', '654321', 'bailey', 'access',
    'flower', '555555', 'passw0rd', 'shadow', 'lovely', '7777777',
    'michael', 'jesus', 'password1', 'superman', 'hello', 'charlie',
    '888888', '696969', 'hottie', 'freedom', 'aa123456', 'qazwsx',
    'ninja', 'azerty', 'loveme', 'whatever', 'donald', 'batman',
    'zaq1zaq1', 'Football', '000000', '123qwe', '987654321', 'mynoob',
    '123321', '18atcskd2w', '3rjs1la7qe', 'google', '1q2w3e4r5t', 'zxcvbnm',
    '1q2w3e', '1111111', 'Iloveyou', 'Qwertyuiop', 'Monkey', 'Dragon',
    'qwerty1', 'secret', '11111111', 'rockyou', 'nicole', 'daniel',
    'babygirl', 'jessica', 'iloveu', 'michelle', 'tigger', 'chocolate',
    'soccer', 'anthony', 'friends', 'butterfly', 'purple', 'angel',
    'jordan', 'liverpool', 'justin', 'fuckyou', 'andrea', 'carlos',
    'jennifer', 'joshua', 'bubbles', 'hannah', 'amanda', 'loveyou',
    'pretty', 'basketball', 'andrew', 'angels', 'tweety', 'playboy',
    'elizabeth', 'tinkerbell', 'samantha', 'barbie', 'chelsea', 'lovers',
    'teamo', 'jasmine', 'brandon', 'melissa', 'eminem', 'matthew',
    'robert', 'danielle', 'forever', 'family', 'jonathan', 'computer',
    'vanessa', 'cookie', 'naruto', 'summer', 'sweety', 'spongebob',
    'joseph', 'junior', 'softball', 'taylor', 'yellow', 'daniela',
    'lauren', 'mickey', 'princesa', 'alexandra', 'alexis', 'estrella',
    'miguel', 'william', 'thomas', 'beautiful', 'mylove', 'angela',
    'poohbear', 'patrick', 'iloveme', 'sakura', 'adrian', 'alexander',
    'destiny', 'christian', 'sayang', 'america', 'dancer', 'monica',
    'richard', 'princess1', 'diamond', 'carolina', 'steven', 'rangers',
    'louise', 'orange', '789456', '999999', 'shorty', '11111',
    'nathan', 'snoopy', 'gabriel', 'hunter', 'cherry', 'killer',
    'sandra', 'alejandro', 'buster', 'george', 'brittany', 'alejandra',
    'patricia', 'rachel', 'tequiero', 'cheese', '159753', 'arsenal',
    'dolphin', 'antonio', 'heather', 'david', 'ginger', 'stephanie',
    'peanut', 'blink182', 'sweetie', '222222', 'beauty', '987654',
    'victoria', 'honey', '00000', 'fernando', 'pokemon', 'maggie',
    'corazon', 'chicken', 'pepper', 'cristina', 'rainbow', 'kisses',
    'manuel', 'myspace', 'rebelde', 'angel1', 'ricardo', 'babygurl',
    'heaven', '55555', 'martin', 'greenday', 'november', 'alyssa',
    'madison', 'mother', '123abc', 'mahalkita', 'september', 'december',
    'morgan', 'mariposa', 'maria', 'gabriela', 'iloveyou2', 'jeremy',
    'pamela', 'kimberly', 'gemini', 'shannon', 'pictures', 'asshole',
    'sophie', 'jessie', 'hellokitty', 'claudia', 'babygirl1', 'angelica',
    'austin', 'mahalko', 'victor', 'horses', 'tiffany', 'mariana',
    'eduardo', 'andres', 'courtney', 'booboo', 'kissme', 'harley',
    'ronaldo', 'iloveyou1', 'precious', 'october', 'inuyasha', 'peaches',
    'veronica', 'chris', 'adriana', 'cutie', 'james', 'banana',
    'prince', 'friend', 'jesus1', 'crystal', 'celtic', 'edward',
    'oliver', 'diana', 'samsung', 'angelo', 'kenneth', 'scooby',
    'carmen', '456789', 'sebastian', 'rebecca', 'jackie', 'spiderman',
    'christopher', 'karina', 'johnny', 'hotmail', '0123456789', 'school',
    'barcelona', 'august', 'orlando', 'samuel', 'cameron', 'slipknot',
    'cutiepie', 'monkey1', '50cent', 'bonita', 'kevin', 'bitch',
    'maganda', 'babyboy', 'casper', 'brenda', 'adidas', 'kitten',
    'karen', 'isabel', 'natalie', 'cuteako', 'javier', '789456123',
    '123654', 'sarah', 'bowwow', 'portugal', 'laura', '777777',
    'marvin', 'denise', 'tigers', 'volleyball', 'jasper', 'rockstar',
    'january', 'fuckoff', 'alicia', 'nicholas', 'flowers', 'cristian',
    'tintin', 'bianca', 'chrisbrown', 'chester', '101010', 'smokey',
    'silver', 'internet', 'sweet', 'strawberry', 'garfield', 'dennis',
    'panget', 'francis', 'cassie', 'benfica', 'love123', 'asdfgh',
    'lollipop', 'olivia', 'cancer', 'camila', 'superstar', 'harrypotter',
    'ihateyou', 'charles', 'monique', 'midnight', 'vincent', 'christine',
    'apples', 'scorpio', 'jordan23', 'lorena', 'andreea', 'mercedes',
    'katherine', 'charmed', 'abigail', 'rafael', 'icecream', 'mexico',
    'brianna', 'nirvana', 'aaliyah', 'pookie', 'johncena', 'lovelove',
    'fucker', 'abcdef', 'benjamin', '131313', 'gangsta', 'brooke',
    '333333', 'hiphop', 'aaaaaa', 'mybaby', 'sergio', 'metallica',
    'julian', 'travis', 'myspace1', 'babyblue', 'sabrina', 'michael1',
    'jeffrey', 'stephen', 'love', 'dakota', 'catherine', 'badboy',
    'fernanda', 'westlife', 'blondie', 'sasuke', 'smiley', 'jackson',
    'simple', 'melanie', 'steaua', 'dolphins', 'roberto', 'fluffy',
    'teresa', 'piglet', 'ronald', 'slideshow', 'asdfghjkl', 'minnie',
    'newyork', 'jason', 'raymond', 'santiago', 'jayson', '88888888',
    '5201314', 'jerome', 'gandako', 'muffin', 'gatita', 'babyko',
    '246810', 'sweetheart', 'chivas', 'ladybug', 'kitty', 'popcorn',
    'alberto', 'valeria', 'leslie', 'jenny', 'nicole1', '12345678910',
    'leonardo', 'jayjay', 'liliana', 'dexter', 'sexygirl', '232323',
    'amores', 'rockon', 'christ', 'babydoll', 'anthony1', 'marcus',
    'bitch1', 'fatima', 'miamor', 'lover', 'chris1', 'single',
    'eeyore', 'lalala', '252525', 'scooter', 'natasha', 'skittles',
    'brooklyn', 'colombia', '159357', 'teddybear', 'winnie', 'happy',
    'manutd', '123456a', 'britney', 'katrina', 'christina', 'pasaway',
    'cocacola', 'mahal', 'grace', 'linda', 'albert', 'tatiana',
    'london', 'cantik', '0123456', 'lakers', 'marie', 'teiubesc',
    '147258369', 'charlotte', 'natalia', 'francisco', 'amorcito', 'smile',
    'paola', 'angelito', 'manchester', 'hahaha', 'elephant', 'mommy1',
    'shelby', '147258', 'kelsey', 'genesis', 'amigos', 'snickers',
    'xavier', 'turtle', 'marlon', 'linkinpark', 'claire', 'stupid',
    '147852', 'marina', 'garcia', 'fuckyou1', 'diego', 'brandy',
    'hockey', '444444', 'sharon', 'bonnie', 'spider', 'iverson',
    'andrei', 'justine', 'frankie', 'pimpin', 'disney', 'rabbit',
    '54321', 'fashion', 'soccer1', 'red123', 'bestfriend', 'england',
    'hermosa', '456123', 'bandit', 'danny', 'allison', 'emily',
    '102030', 'lucky1', 'sporting', 'miranda', 'dallas', 'hearts',
    'camille', 'wilson', 'potter', 'pumpkin', 'iloveu2', 'number1',
    'katie', 'guitar', '212121', 'truelove', 'jayden', 'savannah',
    'hottie1', 'phoenix', 'monster', 'player', 'ganda', 'people',
    'scotland', 'nelson', 'jasmin', 'timothy', 'onelove', 'ilovehim',
    'shakira', 'estrellita', 'bubble', 'smiles', 'brandon1', 'sparky',
    'barney', 'sweets', 'parola', 'evelyn', 'familia', 'love12',
    'nikki', 'motorola', 'florida', 'omarion', 'monkeys', 'loverboy',
    'elijah', 'joanna', 'canada', 'ronnie', 'mamita', 'emmanuel',
    'thunder', '999999999', 'broken', 'rodrigo', 'maryjane', 'westside',
    'california', 'lucky', 'mauricio', 'yankees', 'jackass', 'jamaica',
    'justin1', 'amigas', 'preciosa', 'shopping', 'flores', 'mariah',
    'matrix', 'isabella', 'tennis', 'trinity', 'jorge', 'sunflower',
    'kathleen', 'bradley', 'cupcake', 'hector', 'martinez', 'elaine',
    'robbie', 'friendster', 'cheche', 'gracie', 'connor', 'hello1',
    'valentina', 'melody', 'darling', 'sammy', 'jamie', 'santos',
    'abcdefg', 'joanne', 'candy', 'fuckyou2', 'loser', 'dominic',
    'pebbles', 'sunshine1', 'swimming', 'millie', 'loving', 'gangster',
    'blessed', 'compaq', 'taurus', 'gloria', 'tyler', 'aaron',
    'darkangel', 'kitkat', 'megan', 'dreams', 'sweetpea', 'bettyboop',
    'jessica1', 'cynthia', 'cheyenne', 'ferrari', 'dustin', 'iubire',
    'a123456', 'snowball', 'purple1', 'violet', 'darren', 'bestfriends',
    'inlove', 'kelly', 'batista', 'karla', 'sophia', 'chacha',
    'biteme', 'marian', 'sydney', 'sexyme', 'pogiako', 'gerald',
    'jordan1', '010203', 'daddy1', 'zachary', 'daddysgirl', 'billabong',
    'carebear', 'froggy', 'pinky', 'erika', 'oscar', 'skater',
    'raiders', 'nenita', 'tigger1', 'ashley1', 'charlie1', 'gatito',
    'lokita', 'maldita', 'buttercup', 'nichole', 'bambam', 'nothing',
    'glitter', 'bella', 'amber', 'apple', '123789', 'sister',
    'zacefron', 'tokiohotel', 'loveya', 'lindsey', 'money', 'lovebug',
    'bubblegum', 'marissa', 'dreamer', 'darkness', 'cecilia', 'lollypop',
    'nicolas', 'lindsay', 'cooper', 'passion', 'kristine', 'green',
    'puppies', 'ariana', 'fuckme', 'chubby', 'raquel', 'lonely',
    'anderson', 'sammie', 'sexybitch', 'mario', 'butter', 'willow',
    'roxana', 'mememe', 'caroline', 'susana', 'kristen', 'baller',
    'hotstuff', 'carter', 'stacey', 'babylove', 'angelina', 'miller',
    'scorpion', 'sierra', 'playgirl', 'sweet16', '012345', 'rocker',
    'bhebhe', 'gustavo', 'marcos', 'chance', 'kayla', 'james1',
    'football1', 'eagles', 'loveme1', 'milagros', 'stella', 'lilmama',
    'beyonce', 'lovely1', 'rocky', 'daddy', 'catdog', 'armando',
    'margarita', '151515', 'loves', 'lolita', '202020', 'gerard',
    'undertaker', 'amistad', 'williams', 'freddy', 'capricorn', 'caitlin',
    'bryan', 'delfin', 'dance', 'cheerleader', 'password2', 'PASSWORD',
    'martha', 'lizzie', 'georgia', 'matthew1', 'enrique', 'zxcvbn',
    'badgirl', 'andrew1', '141414', 'dancing', 'cuteme', 'booger',
    'amelia', 'vampire', 'skyline', 'chiquita', 'angeles', 'scoobydoo',
    'janine', 'tamara', 'carlitos', 'money1', 'sheila', 'justme',
    'ireland', 'kittycat', 'hotdog', 'yamaha', 'tristan', 'harvey',
    'israel', 'legolas', 'michelle1', 'maddie', 'angie', 'cinderella',
    'jesuschrist', 'lester', 'ashton', 'ilovejesus', 'tazmania', 'remember',
    'xxxxxx', 'tekiero', 'thebest', 'princesita', 'lucky7', 'jesucristo',
    'peewee', 'paloma', 'buddy1', 'deedee', 'miriam', 'april',
    'patches', 'regina', 'janice', 'cowboys', 'myself', 'lipgloss',
    'jazmin', 'rosita', 'happy1', 'felipe', 'chichi', 'pangit',
    'mierda', 'genius', '741852963', 'hernandez', 'awesome', 'walter',
    'tinker', 'arturo', 'silvia', 'melvin', 'celeste', 'pussycat',
    'gorgeous', 'david1', 'molly', 'honeyko', 'mylife', 'animal',
    'penguin', 'babyboo', 'loveu', 'simpsons', 'lupita', 'boomer',
    'panthers', 'hollywood', 'alfredo', 'musica', 'johnson', 'ilovegod',
    'hawaii', 'sparkle', 'kristina', 'sexymama', 'crazy', 'valerie',
    'spencer', 'scarface', 'hardcore', '098765', '00000000', 'winter',
    'hailey', 'trixie', 'hayden', 'micheal', 'wesley', '242424',
    '0987654321', 'marisol', 'nikita', 'daisy', 'jeremiah', 'pineapple',
    'mhine', 'isaiah', 'christmas', 'cesar', 'lolipop', 'butterfly1',
    'chloe', 'lawrence', 'xbox360', 'sheena', 'murphy', 'madalina',
    'anamaria', 'gateway', 'debbie', 'yourmom', 'blonde', 'jasmine1',
    'please', 'bubbles1', 'jimmy', 'beatriz', 'poopoo', 'diamonds',
    'whitney', 'friendship', 'sweetness', 'pauline', 'desiree', 'trouble',
    '741852', 'united', 'marley', 'brian', 'barbara', 'hannah1',
    'bananas', 'julius', 'leanne', 'sandy', 'marie1', 'anita',
    'lover1', 'chicago', 'twinkle', 'pantera',
]

# worker state shared between the main process and the brute force pool.
# _init_worker() is called once per process, then _verify_any() can be
# used directly (inline stages) or from _check_batch (pool workers).
_ZF = None
_TARGET = None
_PATH = None
_FMT = 'zip'


def _init_worker(path, kind, target, is_aes):
    global _ZF, _TARGET, _PATH, _FMT
    _PATH = path
    _FMT = kind
    _TARGET = target
    _ZF = None
    if kind == 'zip':
        opener = pyzipper.AESZipFile if is_aes else zipfile.ZipFile
        _ZF = opener(path)


def _verify_any(pwd):
    if _FMT == 'zip':
        return verify_zip(_ZF, _TARGET, pwd)
    if _FMT == 'rar':
        return verify_rar(_PATH, _TARGET, pwd)
    if _FMT == '7z':
        return verify_7z(_PATH, _TARGET, pwd)
    return False


def _check_batch(batch):
    for pwd in batch:
        if _verify_any(pwd):
            return pwd
    return None


def verify_zip(zf, target, pwd):
    """test a single zip password - wrong passwords raise, so silence = match"""
    try:
        data = zf.read(target, pwd=pwd.encode('utf-8', 'ignore'))
    except Exception:
        return False
    if target.lower().endswith(TEXT_EXTS):
        try:
            data.decode('utf-8')
        except UnicodeDecodeError:
            return False
    return True


def verify_rar(path, target, pwd):
    """test a rar password. target None means even the file list is
    encrypted, so a successful listing already proves the password."""
    try:
        with rarfile.RarFile(path, pwd=pwd) as rf:
            if target is None:
                rf.infolist()
                return True
            data = rf.read(target)
        if target.lower().endswith(TEXT_EXTS):
            data.decode('utf-8')
        return True
    except Exception:
        return False


class _VerifyTimeout(Exception):
    """raised by the SIGALRM guard when a 7z attempt runs too long"""


def _alarm_handler(signum, frame):
    raise _VerifyTimeout()


def verify_7z(path, target, pwd):
    """test a 7z password by extracting one file to a temp dir.
    target None means the archive header itself is encrypted.

    py7zr has a quirk: for some wrong passwords the lzma decoder
    interprets the garbage as an endless stream and loops forever, so
    every attempt is guarded by an alarm on posix systems and treated
    as a wrong password when it takes too long."""
    use_alarm = os.name == 'posix'
    try:
        if use_alarm:
            signal.signal(signal.SIGALRM, _alarm_handler)
            signal.alarm(2)
        with py7zr.SevenZipFile(path, password=pwd) as z:
            if target is None:
                return bool(z.getnames())
            with tempfile.TemporaryDirectory() as td:
                z.extract(td, targets=[target])
                out = os.path.join(td, target)
                if not os.path.isfile(out):
                    return False
                if target.lower().endswith(TEXT_EXTS):
                    with open(out, 'rb') as f:
                        f.read().decode('utf-8')
                return True
    except Exception:
        return False
    finally:
        if use_alarm:
            signal.alarm(0)


# ---------------- terminal colors ----------------

USE_COLOR = True


class C:
    G = '\033[92m'
    R = '\033[91m'
    Y = '\033[93m'
    N = '\033[96m'
    W = '\033[1m'
    RST = '\033[0m'


def paint(s, color):
    if not USE_COLOR or not sys.stdout.isatty():
        return s
    return color + s + C.RST


def fmt(n):
    return f'{n:,}'


# ---------------- candidate generation ----------------

def case_variants(s):
    out = []
    for v in (s, s.lower(), s.upper(), s.title()):
        if v not in out:
            out.append(v)
    return out


def split_word(w):
    """cut a word in half: 'monkey' -> ['mon', 'key']"""
    if len(w) >= 4:
        h = len(w) // 2
        return [w[:h], w[h:]]
    return [w]


def separator_variants(phrase):
    """build the space / dot / mixed variants of a phrase.

    this is the part that catches passwords like 'get.lost' when the
    phrase was written 'get . lost' in a chat or note, or 'pass word'
    style secrets. every word of the phrase is also tried in its
    cut-in-half form so spaced phrases map back to joined passwords
    and the other way around.
    """
    words = phrase.split()
    base = words if len(words) >= 2 else split_word(words[0] if words else phrase)
    out = {phrase}
    # variant where every longer word is cut: 'get lost' -> 'get lo st'
    cut = [' '.join(split_word(w)) if len(w) >= 4 else w for w in base]
    out.add(' '.join(cut))
    for sep in SEPARATORS:
        joined = sep.join(base)
        out.add(joined)
        out.add(joined.upper())
        out.add(joined.title())
        out.add(sep.join(cut))
        if len(base) == 2:
            out.add(base[0] + ' ' + sep + ' ' + base[1])
            out.add(' '.join(cut) + ' ' + sep + ' ' + base[1])
    return out


def leet(word):
    """common character swaps: password -> p@ssw0rd"""
    swaps = {'a': '@', 'o': '0', 'i': '1', 'e': '3', 's': '$'}
    return ''.join(swaps.get(ch, ch) for ch in word)


def mutate(word):
    """common suffix + separator mutations of a single word"""
    out = set()
    for suf in COMMON_SUFFIX:
        out.add(word + suf)
        out.add(word.capitalize() + suf)
        out.add(word.upper() + suf)
    for sep in (' ', '.', '-', '_'):
        if len(word) >= 6:
            out.add(word[:3] + sep + word[3:])
            out.add(word[:len(word) // 2] + sep + word[len(word) // 2:])
    out.add(leet(word))
    out.add(leet(word) + '123')
    return out


def smart_candidates(zip_path, zf=None):
    """archive name, dates, phrase hints and mutated top passwords.
    zf is an optional archive handle used only to read entry dates.

    candidates are tiered: compact high yield guesses run first so slow
    formats (rar / 7z) get a hit quickly, the heavy separator expansion
    runs last."""
    tier1 = []
    tier2 = []
    tier3 = []

    # ---- tier 1: archive name, dates, primary phrase forms ----
    stem = os.path.splitext(os.path.basename(zip_path))[0]
    clean = re.sub(r'[^A-Za-z0-9]+', '', stem)
    if clean:
        tier1.extend(case_variants(clean))
        for suf in ('123', '!', '@', '1234', '2024', '2025', '2026'):
            tier1.append(clean.lower() + suf)
        tier1.append(clean[::-1])
        name_words = re.split(r'[^A-Za-z0-9]+', stem)
        name_words = [w for w in name_words if w]
        if 1 < len(name_words) <= 4:
            for sep in SEPARATORS:
                tier1.append(sep.join(name_words).lower())
                tier1.append(sep.join(name_words).lower() + '123')

    dates = set()
    try:
        dates.add(time.localtime(os.path.getmtime(zip_path)))
    except OSError:
        pass
    try:
        if zf is not None and hasattr(zf, 'infolist'):
            for info in zf.infolist()[:4]:
                if info.date_time:
                    dates.add(time.struct_time((info.date_time[0], info.date_time[1],
                                                info.date_time[2], 0, 0, 0, 0, 0, 0)))
    except Exception:
        pass
    for t in dates:
        dd, mm = f'{t.tm_mday:02d}', f'{t.tm_mon:02d}'
        yyyy, yy = str(t.tm_year), str(t.tm_year)[2:]
        tier1.extend([dd + mm + yyyy, dd + mm + yy, mm + dd + yyyy, mm + dd + yy,
                      yyyy + mm + dd, yyyy, dd + mm, mm + dd, dd + mm + yyyy + '!',
                      f'{dd}.{mm}.{yyyy}', f'{dd}-{mm}-{yyyy}'])

    # primary forms of every phrase: joined, spaced, dotted, cut in half
    for phrase in PHRASE_HINTS:
        words = phrase.split()
        base = words if len(words) >= 2 else split_word(words[0] if words else phrase)
        cut = [' '.join(split_word(w)) if len(w) >= 4 else w for w in base]
        tier1.extend([phrase,
                      ''.join(base), ' '.join(base), '.'.join(base),
                      '-'.join(base), '_'.join(base),
                      ''.join(base).upper(), ''.join(base) + '!',
                      ' '.join(cut), '.'.join(cut), ' '.join(cut).upper(),
                      ' '.join(base) + ' . ' + '.'.join(base)])

    # ---- tier 2: strongest dictionary words with suffixes and leet ----
    for b in BUILTIN_WORDS[:40]:
        for suf in COMMON_SUFFIX:
            tier2.append(b + suf)
        tier2.append(leet(b))

    # ---- tier 3: full separator expansion of the phrase hints ----
    for phrase in PHRASE_HINTS:
        variants = separator_variants(phrase)
        tier3.extend(variants)
        for v in variants:
            for suf in ('!', '1', '123'):
                tier3.append(v + suf)
    for base in BUILTIN_WORDS[:60]:
        tier3.extend(mutate(base))

    seen = set()
    result = []
    for c in tier1 + tier2 + tier3:
        if c and c not in seen:
            seen.add(c)
            result.append(c)
    return result


def dictionary_candidates():
    """built-in list plus every case variant"""
    out = []
    seen = set()
    for base in BUILTIN_WORDS:
        for v in case_variants(base):
            if v not in seen:
                seen.add(v)
                out.append(v)
    return out


def load_bundled_wordlist():
    """passwords.txt / rockyou.txt / wordlist.txt next to this script"""
    here = os.path.dirname(os.path.abspath(__file__))
    for name in ('passwords.txt', 'rockyou.txt', 'wordlist.txt'):
        path = os.path.join(here, name)
        if os.path.isfile(path):
            words = read_wordlist(path)
            if words:
                print(paint(f'[+] bundled wordlist loaded: {name} '
                            f'({fmt(len(words))} entries)', C.N))
                return words
    return []


def read_wordlist(path):
    words = []
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                w = line.rstrip('\r\n')
                if w and not w.startswith('#'):
                    words.append(w)
    except OSError as e:
        print(paint(f'[!] could not read wordlist: {e}', C.R))
    return words


def batched(iterable, size=BATCH_SIZE):
    while True:
        chunk = list(itertools.islice(iterable, size))
        if not chunk:
            return
        yield chunk


def brute_batches(charset, maxlen):
    for length in range(1, maxlen + 1):
        for tup in itertools.product(charset, repeat=length):
            yield ''.join(tup)


def mask_batches(pattern, charset):
    qpos = [i for i, ch in enumerate(pattern) if ch == '?']
    fixed = list(pattern)

    def gen():
        for combo in itertools.product(charset, repeat=len(qpos)):
            chars = fixed[:]
            for pos, ch in zip(qpos, combo):
                chars[pos] = ch
            yield ''.join(chars)

    return gen()


# ---------------- attack runners ----------------

def run_inline(candidates, label):
    """run a candidate list in the main process using _verify_any()"""
    t0 = time.time()
    total = 0
    for pwd in candidates:
        total += 1
        if total % PROGRESS_EVERY == 0:
            rate = total / max(time.time() - t0, 0.001)
            sys.stdout.write(f'\r    [{label}] {fmt(total)} tried | '
                             f'{fmt(int(rate))}/s ')
            sys.stdout.flush()
        if _verify_any(pwd):
            clear_line()
            return pwd, total, time.time() - t0
    clear_line()
    return None, total, time.time() - t0


def run_pool(path, kind, target, is_aes, gen_factory, label, threads):
    t0 = time.time()
    counter = [0]

    def counted(src):
        for b in src:
            counter[0] += len(b)
            yield b

    found = None
    try:
        with mp.Pool(processes=threads, initializer=_init_worker,
                     initargs=(path, kind, target, is_aes)) as pool:
            nxt = PROGRESS_EVERY
            for result in pool.imap_unordered(_check_batch, counted(batched(gen_factory()))):
                if result:
                    found = result
                    pool.terminate()
                    break
                if counter[0] >= nxt:
                    nxt += PROGRESS_EVERY
                    el = time.time() - t0
                    sys.stdout.write(f'\r    [{label}] {fmt(counter[0])} tried | '
                                     f'{fmt(int(counter[0] / max(el, 0.001)))}/s ')
                    sys.stdout.flush()
    except KeyboardInterrupt:
        print(paint('\n[!] interrupted', C.Y))
        return None, counter[0], time.time() - t0
    clear_line()
    return found, counter[0], time.time() - t0


def clear_line():
    sys.stdout.write('\r' + ' ' * 72 + '\r')
    sys.stdout.flush()


# ---------------- archive inspection ----------------

def detect_format(path):
    """identify the archive type from magic bytes, not the file name"""
    try:
        with open(path, 'rb') as f:
            magic = f.read(8)
    except OSError:
        return None
    if magic[:4] == b'Rar!':
        return 'rar'
    if magic[:6] == b'7z\xbc\xaf\x27\x1c':
        return '7z'
    if magic[:2] == b'PK':
        return 'zip'
    return None


def inspect_archive(path, kind):
    if kind == 'zip':
        return inspect_zip(path)
    if kind == 'rar':
        return inspect_rar(path)
    return inspect_7z(path)


def _rar_backend_hint():
    print(paint('    termux : pkg install unrar', C.Y))
    print(paint('    debian : sudo apt install unrar', C.Y))
    print(paint('    windows: install winrar (or unrar.exe) so it is on PATH', C.Y))
    print(paint('    mac    : brew install rar  (or unar)', C.Y))


def _rar_backend_ok(path, target):
    """probe with a bogus password: a password rejection means the
    backend works, RarCannotExec means no unrar tool is installed"""
    try:
        with rarfile.RarFile(path, pwd='__probe__') as rf:
            if target is None:
                rf.infolist()
            else:
                rf.read(target)
        return True
    except rarfile.RarCannotExec:
        print(paint('[x] no rar backend found (unrar / unar / bsdtar)', C.R))
        _rar_backend_hint()
        return False
    except Exception:
        return True  # bogus password was rejected, backend works


def inspect_rar(path):
    if not HAVE_RARFILE:
        print(paint('[x] rar support needs the rarfile package', C.R))
        print(paint('        pip install rarfile', C.W))
        return None
    try:
        rf = rarfile.RarFile(path)
        try:
            infos = rf.infolist()
        except rarfile.PasswordRequired:
            # the file list itself is encrypted, listing is the password test
            if not _rar_backend_ok(path, None):
                return None
            return {'encrypted': True, 'is_aes': False, 'target': None,
                    'header': True, 'enc_count': 0, 'total_count': 0}
        files = [i for i in infos if not i.is_dir()]
        if not files or not rf.needs_password():
            print(paint('[!] this archive is not password protected', C.Y))
            return {'encrypted': False}
        target = min(files, key=lambda i: i.compress_size).filename
        if not _rar_backend_ok(path, target):
            return None
        return {'encrypted': True, 'is_aes': False, 'target': target,
                'header': False, 'enc_count': len(files), 'total_count': len(infos)}
    except rarfile.Error as e:
        print(paint(f'[x] not a valid rar archive: {e}', C.R))
        return None


def inspect_7z(path):
    if not HAVE_PY7ZR:
        print(paint('[x] 7z support needs the py7zr package', C.R))
        print(paint('        pip install py7zr', C.W))
        return None
    names = []
    try:
        with py7zr.SevenZipFile(path) as z:
            names = z.getnames()
            if not names:
                print(paint('[!] this archive is empty', C.Y))
                return {'encrypted': False}
            if z.needs_password():
                return {'encrypted': True, 'is_aes': True, 'target': names[0],
                        'header': False, 'enc_count': len(names),
                        'total_count': len(names)}
            with tempfile.TemporaryDirectory() as td:
                z.extract(td, targets=[names[0]])
            print(paint('[!] this archive is not password protected', C.Y))
            return {'encrypted': False}
    except py7zr.exceptions.PasswordRequired:
        # header encryption: even the listing needs the password
        return {'encrypted': True, 'is_aes': True, 'target': None,
                'header': True, 'enc_count': 0, 'total_count': 0}
    except Exception as e:
        print(paint(f'[x] not a valid 7z archive: {e}', C.R))
        return None


def inspect_zip(zip_path):
    if not os.path.isfile(zip_path):
        print(paint(f'[x] file not found: {zip_path}', C.R))
        return None
    try:
        with zipfile.ZipFile(zip_path) as z:
            infos = z.infolist()
    except Exception as e:
        print(paint(f'[x] not a valid zip archive: {e}', C.R))
        return None

    enc = [i for i in infos if (i.flag_bits & 0x1) and not i.is_dir()]
    if not enc:
        print(paint('[!] this archive is not password protected', C.Y))
        print(paint(f'    open it directly: unzip "{zip_path}"', C.N))
        return {'encrypted': False}

    # 7-zip archives can encrypt the central directory itself
    if any(i.flag_bits & 0x40 for i in enc):
        print(paint('[x] this looks like a 7-zip archive with header encryption', C.R))
        print(paint('    python tools cannot open this format directly.', C.Y))
        print(paint('    use john the ripper (7z2john) or a 7-zip unlocker.', C.Y))
        return None

    is_aes = any(i.compress_type == 99 for i in enc)
    if is_aes and not HAVE_PYZIPPER:
        print(paint('[x] this archive uses AES encryption', C.R))
        print(paint('    install the pyzipper package first:', C.Y))
        print(paint('        pip install pyzipper', C.W))
        return None

    # verify against the smallest encrypted entry - fastest to test
    target = min(enc, key=lambda i: i.compress_size).filename
    return {'encrypted': True, 'is_aes': is_aes, 'target': target,
            'enc_count': len(enc), 'total_count': len(infos)}


# ---------------- result handling ----------------

def save_report(zip_path, password, attack):
    try:
        with open('password_results.txt', 'a', encoding='utf-8') as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {zip_path} -> "
                    f"{password}  (attack: {attack})\n")
        print(paint('[i] saved to password_results.txt', C.N))
    except OSError:
        pass


def extract_all(zip_path, password, kind, is_aes):
    base = os.path.abspath(zip_path)
    stem = os.path.splitext(base)[0]
    out = stem + '_extracted'
    k = 1
    while os.path.exists(out):
        out = f'{stem}_extracted_{k}'
        k += 1
    try:
        if kind == 'zip':
            opener = pyzipper.AESZipFile if is_aes else zipfile.ZipFile
            with opener(zip_path) as z:
                z.extractall(out, pwd=password.encode('utf-8'))
        elif kind == 'rar':
            with rarfile.RarFile(zip_path, pwd=password) as rf:
                rf.extractall(out)
        else:
            with py7zr.SevenZipFile(zip_path, password=password) as z:
                z.extractall(out)
        n = sum(len(files) for _, _, files in os.walk(out))
        print(paint(f'[+] extracted {n} files to: {out}', C.G))
    except Exception as e:
        print(paint(f'[!] extraction failed: {e}', C.R))
        print(paint(f'    manual: {manual_cmd(zip_path, password)}', C.Y))


def manual_cmd(zip_path, password):
    if zip_path.lower().endswith('.rar'):
        return f'unrar x -p"{password}" "{zip_path}"'
    if zip_path.lower().endswith('.7z'):
        return f'7z x -p"{password}" "{zip_path}" -oout'
    return f'unzip -P "{password}" "{zip_path}" -d out'


def found_banner(password, tries, secs, attack):
    width = max(len(password) + 20, 40)
    print()
    print(paint('+' + '=' * width + '+', C.G))
    print(paint('|' + ' PASSWORD FOUND '.center(width) + '|', C.G))
    print(paint('|' + f'  {password} '.ljust(width) + '|', C.G))
    print(paint('+' + '=' * width + '+', C.G))
    print(paint(f'    attack: {attack} | {fmt(tries)} tried | {secs:.1f}s', C.N))


def finish(zip_path, password, tries, secs, attack, kind, is_aes, do_extract, zf):
    found_banner(password, tries, secs, attack)
    save_report(zip_path, password, attack)
    try:
        if zf is not None:
            zf.close()
    except Exception:
        pass
    if do_extract:
        extract_all(zip_path, password, kind, is_aes)
    else:
        print(paint(f'    manual: {manual_cmd(zip_path, password)}', C.N))


# ---------------- ui helpers ----------------

def banner():
    print(paint('  archive_cracker ' + __version__ + ' - zip / rar / 7z password recovery', C.W))
    print(paint('  smart | dictionary | wordlist | mask | brute force', C.N))
    print()


def ask(prompt, default=''):
    try:
        ans = input(paint(prompt, C.W)).strip().strip('"').strip("'")
        return ans if ans else default
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)


def yes(prompt):
    return ask(prompt + ' (y/n): ').lower().startswith('y')


# ---------------- main ----------------

def main():
    global USE_COLOR
    args = parse_args()
    USE_COLOR = not args.no_color
    if os.name == 'nt':
        os.system('')  # enable ANSI colors on windows terminals

    mp.freeze_support()
    threads = args.threads or max((os.cpu_count() or 4), 2)
    interactive = args.archive is None

    if interactive:
        banner()
        print('path of the locked archive (zip / rar / 7z):')
        zip_path = os.path.abspath(ask('> '))
    else:
        zip_path = os.path.abspath(os.path.expanduser(args.archive))

    if not os.path.isfile(zip_path):
        print(paint(f'[x] file not found: {zip_path}', C.R))
        return

    kind = detect_format(zip_path)
    if kind is None:
        print(paint('[x] unsupported file type - this tool reads zip, rar and 7z archives', C.R))
        return

    info = inspect_archive(zip_path, kind)
    if info is None or not info.get('encrypted'):
        return

    wordlist = args.wordlist or ''
    mask = args.mask or ''
    do_brute = args.brute
    maxlen = args.maxlen
    charset_sel = ''.join(sorted(set(c for c in args.charset.lower()
                                      if c in 'luds'))) or 'ld'
    do_extract = args.extract

    if interactive:
        print()
        wordlist = ask('wordlist file? (enter to skip): ')
        mask = ask("mask pattern? e.g. pass??? (enter to skip): ")
        do_brute = yes('run brute force at the end?')
        if do_brute:
            m = ask('max length? (default 4): ', '4')
            maxlen = int(m) if m.isdigit() else 4
            cs = ask('charset l/u/d/s (default ld): ', 'ld')
            charset_sel = ''.join(sorted(set(c for c in cs.lower()
                                             if c in 'luds'))) or 'ld'
        do_extract = yes('auto-extract files when found?')

    is_aes = info['is_aes']
    target = info['target']
    if kind == 'zip':
        enc_type = 'AES (winzip)' if is_aes else 'ZipCrypto'
    elif kind == 'rar':
        enc_type = 'RAR encryption'
    else:
        enc_type = '7z AES'
    print(paint(f'[+] format: {kind} | encryption: {enc_type} | '
                f'{info["enc_count"]}/{info["total_count"]} files locked', C.N))
    if info.get('header'):
        print(paint('[+] the file list itself is encrypted (header encryption)', C.N))
    print(paint(f'[+] test target: {target if target else "archive listing"}', C.N))
    print(paint(f'[+] workers: {threads} | charset: {charset_sel}', C.N))
    if kind == 'rar':
        print(paint('[i] rar note: every attempt runs the unrar backend, expect 20-100 tries/sec', C.Y))
    if kind == '7z':
        print(paint('[i] 7z note: expensive key derivation, expect 2-15 tries/sec', C.Y))
        if os.name != 'posix':
            print(paint('[i] 7z note: on windows a rare wrong password can stall an attempt,', C.Y))
            print(paint('    linux / termux / mac have a timeout guard against that', C.Y))
    print()

    # archive handle for the smart hints stage (entry dates), when listing
    # is possible without a password
    zf = None
    if kind == 'zip':
        opener = pyzipper.AESZipFile if is_aes else zipfile.ZipFile
        zf = opener(zip_path)
    elif kind == 'rar' and not info.get('header'):
        try:
            zf = rarfile.RarFile(zip_path)
        except Exception:
            zf = None

    # set the shared verifier state for the inline stages
    _init_worker(zip_path, kind, target, is_aes)
    charset = ''.join(CHARSETS[c] for c in charset_sel)
    found = None

    # stage 1 - smart hints
    print(paint('[1/6] smart hints (name, dates, phrases)...', C.W))
    found, tries, secs = run_inline(smart_candidates(zip_path, zf), 'smart')
    if found:
        finish(zip_path, found, tries, secs, 'smart', kind, is_aes, do_extract, zf)
        return

    # stage 2 - built-in dictionary
    print(paint('[2/6] built-in dictionary...', C.W))
    found, tries, secs = run_inline(dictionary_candidates(), 'dict')
    if found:
        finish(zip_path, found, tries, secs, 'dict', kind, is_aes, do_extract, zf)
        return

    # stage 3 - bundled wordlist next to the script
    bundled = load_bundled_wordlist()
    if bundled:
        print(paint('[3/6] bundled wordlist...', C.W))
        found, tries, secs = run_inline(bundled, 'bundled')
        if found:
            finish(zip_path, found, tries, secs, 'bundled', kind, is_aes, do_extract, zf)
            return
    else:
        print(paint('[3/6] no bundled wordlist found (skipped)', C.N))

    # stage 4 - user wordlist
    if wordlist:
        words = read_wordlist(wordlist)
        print(paint(f'[4/6] wordlist: {wordlist} ({fmt(len(words))} entries)', C.W))
        found, tries, secs = run_inline(words, 'wordlist')
        if found:
            finish(zip_path, found, tries, secs, 'wordlist', kind, is_aes, do_extract, zf)
            return
    else:
        print(paint('[4/6] no wordlist given (skipped)', C.N))

    # stage 5 - mask
    if mask:
        space = len(charset) ** mask.count('?')
        print(paint(f'[5/6] mask {mask!r} ({fmt(space)} combinations)', C.W))
        found, tries, secs = run_pool(zip_path, kind, target, is_aes,
                                      lambda: mask_batches(mask, charset),
                                      'mask', threads)
        if found:
            finish(zip_path, found, tries, secs, 'mask', kind, is_aes, do_extract, zf)
            return
    else:
        print(paint('[5/6] no mask given (skipped)', C.N))

    # stage 6 - brute force
    if do_brute:
        print(paint(f'[6/6] brute force (max {maxlen} chars, charset {charset_sel})', C.W))
        if kind in ('rar', '7z'):
            print(paint('    [!] brute force is very slow on this format, prefer mask or wordlist', C.Y))
        # pins first, they are very common
        print(paint('    phase A: digits only (pin style)...', C.N))
        found, tries, secs = run_pool(zip_path, kind, target, is_aes,
                                      lambda: brute_batches(CHARSETS['d'], min(maxlen, 6)),
                                      'brute-digits', threads)
        if found:
            finish(zip_path, found, tries, secs, 'brute-digits', kind, is_aes, do_extract, zf)
            return
        space = sum(len(charset) ** n for n in range(1, maxlen + 1))
        print(paint(f'    phase B: full charset ({fmt(space)} combinations)', C.N))
        if space > 300_000_000:
            print(paint('    [!] search space is huge, this can take hours or days', C.Y))
        found, tries, secs = run_pool(zip_path, kind, target, is_aes,
                                      lambda: brute_batches(charset, maxlen),
                                      'brute', threads)
        if found:
            finish(zip_path, found, tries, secs, 'brute', kind, is_aes, do_extract, zf)
            return
    else:
        print(paint('[6/6] brute force disabled (use -b or answer y)', C.N))

    print()
    print(paint('  password not found', C.R))
    print()
    print(paint('next steps:', C.Y))
    print(f"    partial hint?    python archive_cracker.py \"{zip_path}\" -M 'pass???'")
    print(f'    own guesses?     python archive_cracker.py "{zip_path}" -w mylist.txt')
    print(f'    short password?  python archive_cracker.py "{zip_path}" -b -m 5 -c ld')
    print('    get rockyou.txt and pass it with -w for a 14 million word list')


def parse_args():
    p = argparse.ArgumentParser(
        prog='archive_cracker.py',
        description='recover the password of a locked zip, rar or 7z archive')
    p.add_argument('archive', nargs='?',
                   help='path of the archive (zip / rar / 7z, omit for interactive mode)')
    p.add_argument('-w', '--wordlist', help='custom wordlist file, one password per line')
    p.add_argument('-b', '--brute', action='store_true', help='enable brute force stage')
    p.add_argument('-m', '--maxlen', type=int, default=4,
                   help='max length for brute force / mask (default 4)')
    p.add_argument('-c', '--charset', default='ld',
                   help='charset for brute force: l lower, u upper, d digits, s special')
    p.add_argument('-M', '--mask',
                   help="mask pattern, '?' matches any one character (e.g. 'pass???')")
    p.add_argument('-t', '--threads', type=int, default=0, help='worker processes (default auto)')
    p.add_argument('-x', '--extract', action='store_true',
                   help='extract all files automatically once the password is found')
    p.add_argument('--no-color', action='store_true', help='disable colored output')
    return p.parse_args()


if __name__ == '__main__':
    main()

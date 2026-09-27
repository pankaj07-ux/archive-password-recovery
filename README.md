# 🔐 archive-password-recovery

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License: MIT">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Termux%20%7C%20Windows%20%7C%20macOS-orange?style=for-the-badge" alt="Platforms">
  <img src="https://img.shields.io/badge/Formats-ZIP%20%7C%20RAR%20%7C%207Z-purple?style=for-the-badge" alt="Supported Formats">
</p>

<p align="center">
  <b>Command line tool to recover the password of a locked archive when you own the file but lost the password.</b>
</p>

---

### 📦 Supported Formats

- **ZIP** – classic ZipCrypto and AES encrypted (WinZip style)
- **RAR** – RAR3 and RAR5, including archives with encrypted file lists
- **7Z** – AES encrypted archives, header encrypted or content encrypted

A lot of locked archives floating around Telegram and Discord are not protected with a serious password at all. The password is a short phrase, a joke, or the archive name with a couple of numbers, and when someone writes it down in chat they scatter random spaces and dots between the letters. 

This tool is built around that reality: **it tries the cheap and human stuff first and only falls back to slow brute force at the end.**

---

## 💡 How It Works

The tool runs **six stages in order**, cheapest first, and stops the moment a password verifies:

```
[ Stage 1: Smart ] ➔ [ Stage 2: Dictionary ] ➔ [ Stage 3: Bundled 5K+ ] ➔ [ Stage 4: Wordlist ] ➔ [ Stage 5: Mask ] ➔ [ Stage 6: Brute Force ]
```

| Stage | What It Tries | Catches |
|:------|:--------------|:--------|
| **1. smart** | Archive name, dates, common phrases and mutations of both | `get.lost`, `backup123`, `24092026` |
| **2. dictionary** | Built-in list of the most common and most leaked passwords | `P@ssw0rd`, `Aa123456`, `monkey` |
| **3. bundled** | `passwords.txt` shipped in this repo (5000+ entries) | Deeper RockYou hits |
| **4. wordlist** | Your own list with `-w` | Personal guesses & custom wordlists |
| **5. mask** | A pattern with `?` wildcards | Known prefix like `pass???` |
| **6. brute force** | Full search over a charset, digit PINs first | Short passwords & numeric PINs |

### 🧠 Smart Mutation & Detection Details

- **Stage 1 (Smart)** is the interesting one: Every candidate is expanded into its space / dot / dash / mixed variants, so a phrase written as `get . lost` in a chat or note maps back to passwords like `get.lost`, `getlost`, `Get.Lost` and similar.
- Spaces and special characters in passwords are fully supported in the brute force stage too (`-c s`).
- The archive format is detected from the file's **magic bytes**, not from its name or file extension, so even a renamed file works seamlessly.

---

## 📥 Installation

Python **3.8 or newer** is the only hard requirement. The rest depends on the formats you need:

```bash
pip install pyzipper rarfile py7zr
```

### Dependencies Breakdown

| Format | Needs | Notes |
|:-------|:------|:------|
| **ZIP (ZipCrypto)** | Nothing | Built-in standard library |
| **ZIP (AES)** | `pyzipper` | `pip install pyzipper` |
| **RAR** | `rarfile` + an `unrar` binary | Termux: `pkg install unrar`<br>Debian/Ubuntu: `sudo apt install unrar`<br>Windows: Install WinRAR<br>macOS: `brew install rar` |
| **7Z** | `py7zr` | Pure Python, no binary needed |

#### 📱 Setup on Android (Termux):

```bash
pkg install python unrar
pip install pyzipper rarfile py7zr
```

---

## 🛠️ Usage

### 🎯 Interactive Mode
Just run without arguments and answer the prompts:
```bash
python archive_cracker.py
```

### ⚡ Direct Command-Line Execution
```bash
python archive_cracker.py locked.zip
python archive_cracker.py locked.rar -x
python archive_cracker.py locked.7z -w myguesses.txt
python archive_cracker.py locked.zip -M 'pass???'
python archive_cracker.py locked.zip -b -m 5 -c luds
```

### ⚙️ Command-Line Options

| Flag | Meaning |
|:-----|:--------|
| `-w FILE` | Wordlist, one password per line |
| `-M PATTERN` | Mask, `?` matches any one character |
| `-b` | Enable brute force stage |
| `-m N` | Max password length for brute force (default: `4`) |
| `-c CHARS` | Charset: `l` (lower), `u` (upper), `d` (digits), `s` (special) |
| `-t N` | Number of worker processes (default: CPU count) |
| `-x` | Extract all files once the password is found |
| `--no-color` | Plain output without terminal colors |

> [!NOTE]
> A found password is printed, automatically appended to `password_results.txt`, and with `-x` the archive is automatically extracted to `<name>_extracted/`.

---

## ⚡ Speed & Benchmarks

*Rough benchmark numbers on an average laptop (two cores):*

| Format | Tries per Second | Why |
|:-------|:-----------------|:----|
| **ZIP (ZipCrypto)** | `50k - 150k` | Password check is nearly free |
| **ZIP (AES)** | `5k - 15k` | Key derivation per attempt |
| **RAR** | `20 - 100` | Every attempt runs the unrar backend |
| **7Z** | `2 - 15` | Expensive key derivation plus one extraction per attempt |

Because of that, **brute force beyond 4-5 characters is only realistic for ZipCrypto**. For the slow formats, prefer the smart stage, a wordlist (`-w`), or a mask (`-M`). For serious recovery of a long random password, extract the hash and use John the Ripper or Hashcat.

### ⚠️ A Note on `py7zr`:
One `py7zr` quirk is worth knowing: for some wrong passwords its LZMA decoder loops forever on the decrypted garbage. This tool guards every 7z attempt with a **timeout on Linux / Termux / macOS**, so a hanging attempt just counts as a wrong password. On Windows that guard does not exist, so a rare candidate may stall a run there.

---

## 📚 Wordlist Sources

`passwords.txt` was compiled from public "most common passwords" research and leak lists, then de-duplicated:

- **RockYou.txt** top entries (the classic 32 million account leak)
- **NordPass** top 200 list (2024 release)
- **SplashData** worst passwords of the year lists
- **UK NCSC** breached password analysis list

It is small on purpose so the bundled stage finishes in seconds. For serious recovery, grab the full `rockyou.txt` (about 134 MB, 14 million entries) and pass it yourself:

```bash
python archive_cracker.py locked.zip -w rockyou.txt
```

---

## ⚠️ Limitations

- **7-Zip Zip Archives with Encrypted Headers:** 7-Zip ZIPs with header encryption (flag `0x40`, created by 7-Zip's zip writer) are detected and skipped with a hint towards John the Ripper.
- **Backslash Exclusion:** The brute force charset deliberately omits the backslash character.
- **RAR Backend Requirement:** RAR requires an `unrar` binary on the system; the tool will tell you what is missing and how to install it.

---

## ⚖️ Legal & Disclaimer

> [!IMPORTANT]
> Only use this on archives you own or have explicit permission to unlock. Recovering your own lost password is fine, breaking into other people's files is not. The wordlists shipped here are compiled from already public breach research; no passwords were stolen for this project.

---

## 👤 Author

**Pankaj Sah** – GitHub: [@pankaj07-ux](https://github.com/pankaj07-ux)

Pull requests are welcome, especially wordlist additions from new public breach reports!

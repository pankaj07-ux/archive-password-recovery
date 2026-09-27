# 🔐 archive-password-recovery

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License: MIT">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Termux%20%7C%20Windows%20%7C%20macOS-orange?style=for-the-badge" alt="Platforms">
  <img src="https://img.shields.io/badge/Formats-ZIP%20%7C%20RAR%20%7C%207Z-purple?style=for-the-badge" alt="Supported Formats">
</p>

<p align="center">
  <b>A lightweight, high-performance command-line tool to recover lost passwords for locked archives using an intelligent multi-stage pipeline.</b>
</p>

---

## 🚀 Key Highlights

- ⚡ **Multi-Stage Recovery:** Runs 6 progressive stages from cheapest heuristics to deeper checks.
- 🧠 **Smart Mutation Engine:** Automatically detects patterns like spaced words (`g e t . l o s t`), dots, dates, and common phrase mutations.
- 📦 **Multi-Format Support:**
  - **ZIP** – Classic ZipCrypto and WinZip AES encryption.
  - **RAR** – RAR3 and RAR5 (including encrypted file lists).
  - **7Z** – AES encrypted archives (header and content encrypted).
- 🔍 **Format Auto-Detection:** Reads magic bytes directly—works even if the file extension is wrong or missing.
- 📱 **Mobile & Termux Friendly:** Works out-of-the-box on Android via Termux as well as desktop systems.

---

## 💡 How It Works

The tool runs **six stages in order**, cheapest first, and halts the instant a correct password verifies:

```
[ Stage 1: Smart Heuristics ] ➔ [ Stage 2: Top Common ] ➔ [ Stage 3: Bundled 5K+ ] ➔ [ Stage 4: Wordlist ] ➔ [ Stage 5: Mask ] ➔ [ Stage 6: Brute-Force ]
```

| # | Stage | What It Tries | Best Catches |
|---|-------|---------------|--------------|
| **1** | **Smart** | Archive filename, dates, seller/chat phrases & variants | `get.lost`, `backup123`, `24092026` |
| **2** | **Dictionary** | Built-in list of the most frequent leaked passwords | `P@ssw0rd`, `Aa123456`, `monkey` |
| **3** | **Bundled** | Curated `passwords.txt` shipped in repo (5,000+ entries) | High-probability RockYou hits |
| **4** | **Wordlist** | Custom user-supplied wordlist (`-w file.txt`) | Personal guesses & larger breach dumps |
| **5** | **Mask** | Custom pattern matching with `?` wildcards | Known formats like `pass???` |
| **6** | **Brute Force** | Exhaustive search over character sets, digit PINs first | Short combinations & PINs |

> [!NOTE]
> **Stage 1 (Smart)** expands candidate phrases into spaces, dots, dashes, and case variations. For example, a chat taunt written as `get . lost` automatically tests `get.lost`, `getlost`, `Get.Lost`, etc.

---

## 📥 Installation

Python **3.8 or newer** is required.

```bash
# Clone the repository
git clone https://github.com/pankaj07-ux/archive-password-recovery.git
cd archive-password-recovery

# Install Python dependencies
pip install -r requirements.txt
```

### Format Dependencies

| Format | Requirements | Setup Notes |
|--------|--------------|-------------|
| **ZIP (ZipCrypto)** | None | Standard Python library |
| **ZIP (AES)** | `pyzipper` | `pip install pyzipper` |
| **RAR** | `rarfile` + `unrar` binary | Termux: `pkg install unrar`<br>Debian/Ubuntu: `sudo apt install unrar`<br>macOS: `brew install rar`<br>Windows: Install WinRAR |
| **7Z** | `py7zr` | Pure Python (`pip install py7zr`) |

#### Quick setup for Termux (Android):
```bash
pkg install python unrar
pip install -r requirements.txt
```

---

## 🛠️ Usage

### 🎯 Interactive Mode
Simply run the script and follow the guided prompts:
```bash
python archive_cracker.py
```

### ⚡ Command Line Options
```bash
# Basic recovery
python archive_cracker.py locked.zip

# Recover and automatically extract contents on success
python archive_cracker.py locked.rar -x

# Using a custom wordlist
python archive_cracker.py locked.7z -w myguesses.txt

# Mask attack (? matches any character)
python archive_cracker.py locked.zip -M 'pass???'

# Brute-force mode (length up to 5, digits + lowercase + uppercase + special)
python archive_cracker.py locked.zip -b -m 5 -c luds
```

### ⚙️ Command-Line Flags

| Flag | Argument | Description |
|------|----------|-------------|
| `-w` | `FILE` | Path to custom wordlist (one per line) |
| `-M` | `PATTERN` | Mask pattern (`?` matches any character) |
| `-b` | — | Enable brute-force stage |
| `-m` | `N` | Maximum password length for brute-force (default: `4`) |
| `-c` | `CHARS` | Charset: `l` (lower), `u` (upper), `d` (digits), `s` (special) |
| `-t` | `N` | Worker process count (default: CPU count) |
| `-x` | — | Automatically extract archive after finding password |
| `--no-color` | — | Disable terminal colors |

---

## ⚡ Speed & Benchmarks

*Approximate benchmark figures on a standard 2-core laptop:*

| Format | Speed | Architecture Notes |
|--------|-------|--------------------|
| **ZIP (ZipCrypto)** | `50,000 - 150,000 / sec` | Extremely fast native verification |
| **ZIP (AES)** | `5,000 - 15,000 / sec` | Per-attempt key derivation |
| **RAR** | `20 - 100 / sec` | Invokes the external unrar engine |
| **7Z** | `2 - 15 / sec` | Heavy key derivation + decompression test |

> [!TIP]
> For heavy or slow formats (RAR / 7Z), prioritize **Smart stage**, **Wordlist (`-w`)**, or **Mask (`-M`)** rather than blind long brute-force.

---

## 📚 Wordlist Sources

The bundled `passwords.txt` is compiled and de-duplicated from public password research:
- Top entries from `rockyou.txt`
- NordPass Most Common Passwords
- SplashData annual lists
- UK NCSC breached credential datasets

For large dictionary attacks, supply the full RockYou wordlist via `-w rockyou.txt`.

---

## ⚠️ Limitations

- **7-Zip Encrypted Headers:** 7-Zip archives created with encrypted file lists (`-mhe=on`) that use non-standard headers are flagged with guidance toward specialized hash extractors.
- **RAR Backend:** Requires the `unrar` binary installed and accessible in your system `PATH`.

---

## ⚖️ Legal & Disclaimer

> [!IMPORTANT]
> This tool is developed strictly for educational and legitimate data recovery purposes (e.g., retrieving access to your own personal files or files you have authorized permission to assess). Unauthorized access to computers or accounts is illegal.

---

## 👤 Author

Developed with care by **Pankaj Sah**  
GitHub: [@pankaj07-ux](https://github.com/pankaj07-ux)

Contributions, issue reports, and wordlist improvements are always welcome!

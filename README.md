# 🔐 Password Strength Checker

A small Python command-line tool that rates how strong a password is and tells you how to improve it.

## Features

- Estimates entropy (in bits) from length and character variety
- Flags passwords found in a common-password list
- Detects sequences (`abc`, `123`) and repeated characters (`aaa`)
- Gives a 5-level rating: Very weak → Very strong, with tips
- Runs fully offline, nothing is saved or sent

## Usage

```bash
python password_checker.py            # type the password hidden
python password_checker.py "MyP@ss2026"
```

Example output:

```
Strength : Strong  [████░]
Entropy  : 65.7 bits
Tips     :
  - Looks good.
```

## Run tests

```bash
python -m unittest -v
```

## Tech

Python 3.10+ (standard library only)

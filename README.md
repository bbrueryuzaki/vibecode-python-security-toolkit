# Vibecode Python Security Toolkit

Full vibecoded with Codex.

A desktop security toolkit built with Python and Tkinter. It runs locally and uses only Python's standard library for its core features. `zxcvbn` is optional and adds pattern-aware password analysis.

## Features

- Generate standard passwords, passphrases, API tokens, PINs, and usernames.
- Check a password locally with entropy and strength estimates; install optional `zxcvbn` for its additional estimate.
- Optionally check whether a password appears in Have I Been Pwned's Pwned Passwords database. The app uses the range API and sends only the first five characters of the password's SHA-1 hash; the full password is not sent.
- Generate random numbers, coin tosses, dice rolls, and casino-style spins with histories.
- Draw tarot cards in one-card, three-card, or Celtic Cross spreads, with upright and reversed card images.

## Requirements

- Python 3.10 or newer
- Tkinter (included with most Windows and macOS Python installers; Linux may package it separately)
- Internet access only for the optional breach lookup
- Optional: `zxcvbn` for pattern-aware password estimates

## Run on Windows

1. Download or clone this repository.
2. Open PowerShell or Command Prompt in the project folder.
3. Run:

   ```powershell
   py password_generator_gui.py
   ```

If `py` is unavailable, use `python password_generator_gui.py`.

## Optional zxcvbn support

Install into the same Python environment used to launch the app:

```powershell
py -m pip install -r requirements-optional.txt
```

The app still runs without this package; its zxcvbn-specific estimate will be unavailable.

## Tarot card images

The images are bundled in `tarot_cards/` so tarot draws work offline. Their source and public-domain status are described in [`tarot_cards/ATTRIBUTION.txt`](tarot_cards/ATTRIBUTION.txt). Keep that attribution file when redistributing the images.

## Privacy

Password generation and local strength checks run on your device. The optional breach check contacts Have I Been Pwned using its range-query design; it sends a partial SHA-1 hash prefix, not the password itself. Do not enable network checks if you do not want the app to make that request.

## License

No software license has been selected for this project yet. Until one is added, GitHub users do not receive permission to reuse, modify, or redistribute the code. Tarot image attribution and status are documented separately.

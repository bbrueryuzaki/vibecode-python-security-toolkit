import secrets
import string
import math
import hashlib
import threading
import tkinter as tk
from pathlib import Path
import urllib.error
import urllib.request
from tkinter import messagebox, ttk

try:
    from zxcvbn import zxcvbn
except ImportError:
    zxcvbn = None


SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"
LEET_TABLE = str.maketrans({
    "a": "4", "A": "4", "e": "3", "E": "3",
    "i": "1", "I": "1", "o": "0", "O": "0",
    "s": "5", "S": "5", "t": "7", "T": "7",
})
MAX_PASSWORDS = 5
# Illustrative offline slow-hash scenario; actual rates depend on the verifier's hash settings.
CRACK_GUESSES_PER_SECOND = 10_000
FAST_HASH_GUESSES_PER_SECOND = 10_000_000_000
ONLINE_GUESSES_PER_HOUR = 100
WORDS = """amber apple autumn bamboo beacon berry birch blossom breeze brook cabin cactus candle canyon captain carpet castle cedar cherry citrus clover coconut comet copper coral cricket crystal daisy daylight delta desert dinner dolphin dragon drift eagle earth echo elm ember emerald engine falcon family feather festival field firefly flower forest fossil fountain freedom friday galaxy garden garlic gentle ginger glacier gold gravel harbor harmony harvest hazel hello highly carlton drinking hidden hill honey horizon island ivory jacket jasmine journey juniper kettle kingdom kitchen lantern lemon liberty lilac linden lobster lotus lumber lunar magic maple marble meadow melody memory mercury midnight mint mirror misty moment mountain music mystery napkin nature nectar nightingale north ocean olive oregano orchid origin otter pancake paper parent pebble pepper phoenix picnic pillow planet plum pocket poetry pond popcorn prairie pumpkin purple puzzle quartz rabbit rainbow raven reason recipe redwood river robin rocket rose saddle saffron sailboat salmon sapphire scarlet season secret shadow shelter silver simple sky smile solar song sparkle sparrow spirit spring squirrel stadium starlight stone summer sunset sweater thunder timber tomato treasure tulip tunnel turtle twilight umbrella valley velvet veranda victory village violet walnut wander waterfall weather whisper willow window winter wonder yellow zephyr""".split()
USERNAME_ADJECTIVES = "agile amber bold brave bright brisk calm clever cozy crafty curious daring dapper eager electric fearless fierce friendly funny gentle golden happy hidden jolly keen kind lively lucky lunar mellow mighty nimble noble playful quick quiet radiant restless rosy savvy silver sly snappy spirited steady sunny swift tender tiny vivid wild wise witty".split()
USERNAME_NOUNS = "badger bear bison bobcat comet coyote cricket dragon eagle falcon fox gecko heron kestrel kitten koala leopard lynx marmot mongoose moon otter owl panda panther parrot penguin phoenix pika rabbit raven robin salmon star tiger toucan turtle wolf wren yak".split()
USERNAME_VERBS = "bouncing drifting dreaming exploring floating galloping gliding humming leaping meandering moonwalking orbiting paddling racing roaming sailing skating soaring sparking spinning sprinting strolling surfing swimming wandering weaving whistling".split()
WORD_SEPARATOR_OPTIONS = (
    ("Hyphen: -", "-"), ("Space", " "), ("Underscore: _", "_"),
    ("Period: .", "."), ("Comma: ,", ","),
    ("Random digit (0–9)", "random_digit"),
    ("Random numbers with symbols", "random_mix"),
)


def make_password(length, use_lower, use_upper, use_digits, use_symbols):
    groups = []
    if use_lower:
        groups.append(string.ascii_lowercase)
    if use_upper:
        groups.append(string.ascii_uppercase)
    if use_digits:
        groups.append(string.digits)
    if use_symbols:
        groups.append(SYMBOLS)

    if not groups:
        raise ValueError("Select at least one character type.")
    if length < len(groups):
        raise ValueError(f"Length must be at least {len(groups)} for the selected types.")

    # Guarantee one character from every selected group, then fill and shuffle.
    chars = [secrets.choice(group) for group in groups]
    alphabet = "".join(groups)
    chars.extend(secrets.choice(alphabet) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


class PasswordGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.missing_dependency_notified = False
        self.progress_style = ttk.Style(root)
        self.progress_style.theme_use("clam")
        root.title("Password and Random Generator")
        root.resizable(True, True)
        root.configure(bg="#f4f6fb")
        root.minsize(360, 260)
        screen_height = root.winfo_screenheight()
        root.geometry(f"440x{min(850, screen_height - 100)}")

        scroll_container = tk.Frame(root, bg="#f4f6fb")
        scroll_container.pack(fill="both", expand=True)
        canvas = tk.Canvas(scroll_container, bg="#f4f6fb", highlightthickness=0)
        scrollbar = tk.Scrollbar(scroll_container, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        frame = tk.Frame(canvas, bg="#f4f6fb", padx=24, pady=22)
        canvas_window = canvas.create_window((0, 0), window=frame, anchor="nw")
        frame.bind("<Configure>", lambda _event: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda event: canvas.itemconfigure(canvas_window, width=event.width))
        canvas.bind_all("<MouseWheel>", lambda event: canvas.yview_scroll(-1 * (event.delta // 120), "units"))

        tk.Label(frame, text="Password and Random Generator", font=("Segoe UI", 19, "bold"),
                 bg="#f4f6fb", fg="#172033").pack(anchor="w")
        tk.Label(frame, text="Create passwords, usernames, API tokens and random numbers on your device.",
                 font=("Segoe UI", 10), bg="#f4f6fb", fg="#586174").pack(anchor="w", pady=(2, 16))

        mode_frame = tk.LabelFrame(frame, text="Generation type", font=("Segoe UI", 9, "bold"),
                                   bg="#f4f6fb", fg="#172033", padx=10, pady=5)
        self.mode_frame = mode_frame
        mode_frame.pack(fill="x", pady=(0, 12))
        self.mode = tk.StringVar(value="standard")
        tk.Radiobutton(mode_frame, text="Standard", variable=self.mode, value="standard",
                       command=self.update_mode, bg="#f4f6fb", activebackground="#f4f6fb",
                       font=("Segoe UI", 10)).pack(side="left")
        tk.Radiobutton(mode_frame, text="Passphrase", variable=self.mode, value="memorable",
                       command=self.update_mode, bg="#f4f6fb", activebackground="#f4f6fb",
                       font=("Segoe UI", 10)).pack(side="left", padx=(12, 0))
        tk.Radiobutton(mode_frame, text="API key / token", variable=self.mode, value="token",
                       command=self.update_mode, bg="#f4f6fb", activebackground="#f4f6fb",
                       font=("Segoe UI", 10)).pack(side="left", padx=(12, 0))
        tk.Radiobutton(mode_frame, text="Username", variable=self.mode, value="username",
                       command=self.update_mode, bg="#f4f6fb", activebackground="#f4f6fb",
                       font=("Segoe UI", 10)).pack(side="left", padx=(12, 0))
        tk.Radiobutton(mode_frame, text="PIN", variable=self.mode, value="pin",
                       command=self.update_mode, bg="#f4f6fb", activebackground="#f4f6fb",
                       font=("Segoe UI", 10)).pack(side="left", padx=(12, 0))
        tk.Radiobutton(mode_frame, text="Random number", variable=self.mode, value="random_number",
                       command=self.update_mode, bg="#f4f6fb", activebackground="#f4f6fb",
                       font=("Segoe UI", 10)).pack(side="left", padx=(12, 0))
        tk.Radiobutton(mode_frame, text="Coin toss", variable=self.mode, value="coin_toss",
                       command=self.update_mode, bg="#f4f6fb", activebackground="#f4f6fb",
                       font=("Segoe UI", 10)).pack(side="left", padx=(12, 0))
        tk.Radiobutton(mode_frame, text="Dice roll", variable=self.mode, value="dice_roll",
                       command=self.update_mode, bg="#f4f6fb", activebackground="#f4f6fb",
                       font=("Segoe UI", 10)).pack(side="left", padx=(12, 0))
        tk.Radiobutton(mode_frame, text="Casino", variable=self.mode, value="casino",
                       command=self.update_mode, bg="#f4f6fb", activebackground="#f4f6fb",
                       font=("Segoe UI", 10)).pack(side="left", padx=(12, 0))
        tk.Radiobutton(mode_frame, text="Tarot", variable=self.mode, value="tarot",
                       command=self.update_mode, bg="#f4f6fb", activebackground="#f4f6fb",
                       font=("Segoe UI", 10)).pack(side="left", padx=(12, 0))

        settings = tk.Frame(frame, bg="#f4f6fb")
        self.settings = settings
        settings.pack(fill="x", pady=(0, 12))

        self.standard_controls = tk.Frame(settings, bg="#f4f6fb")
        self.standard_controls.grid(row=0, column=0, columnspan=2, sticky="ew")
        tk.Label(self.standard_controls, text="Password length", font=("Segoe UI", 10, "bold"),
                 bg="#f4f6fb", fg="#172033").grid(row=0, column=0, sticky="w", pady=3)
        self.length = tk.IntVar(value=20)
        self.length_value = tk.Label(self.standard_controls, textvariable=self.length, width=4,
                                     font=("Segoe UI", 10), bg="#f4f6fb", fg="#172033")
        self.length_value.grid(row=0, column=1, sticky="e", pady=3)
        tk.Scale(self.standard_controls, from_=8, to=256, orient="horizontal", variable=self.length,
                 showvalue=False, length=230, resolution=1, bg="#f4f6fb",
                 highlightthickness=0, troughcolor="#d8deea").grid(
                     row=1, column=0, columnspan=2, sticky="ew", pady=(0, 4))
        presets = tk.Frame(self.standard_controls, bg="#f4f6fb")
        presets.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0, 8))
        for preset in (12, 16, 20, 24, 32, 48, 64, 128, 256):
            tk.Button(presets, text=str(preset), command=lambda value=preset: self.length.set(value),
                      font=("Segoe UI", 8), bg="#e5e9f2", fg="#172033",
                      activebackground="#d5dbea", relief="flat", padx=5, pady=3,
                      cursor="hand2").pack(side="left", expand=True, fill="x", padx=2)

        generation_controls = tk.Frame(frame, bg="#f4f6fb")
        self.generation_controls = generation_controls
        tk.Label(generation_controls, text="Generation amount",
                 font=("Segoe UI", 10, "bold"), bg="#f4f6fb", fg="#172033").grid(
                     row=0, column=0, sticky="w", pady=3)
        self.count = tk.IntVar(value=1)
        self.count_value = tk.Label(generation_controls, textvariable=self.count, width=4,
                                    font=("Segoe UI", 10), bg="#f4f6fb", fg="#172033")
        self.count_value.grid(row=0, column=1, sticky="e", pady=3)
        tk.Scale(generation_controls, from_=1, to=MAX_PASSWORDS, orient="horizontal", variable=self.count,
                 showvalue=False, length=230, resolution=1, bg="#f4f6fb",
                 highlightthickness=0, troughcolor="#d8deea").grid(
                     row=1, column=0, columnspan=2, sticky="ew", pady=(0, 4))
        generation_controls.pack(fill="x", pady=(0, 12))
        options = tk.LabelFrame(frame, text="Include", font=("Segoe UI", 9, "bold"),
                                bg="#f4f6fb", fg="#172033", padx=10, pady=5)
        self.options = options
        options.pack(fill="x", pady=(0, 14))
        self.lower = tk.BooleanVar(value=True)
        self.upper = tk.BooleanVar(value=True)
        self.digits = tk.BooleanVar(value=True)
        self.symbols = tk.BooleanVar(value=True)
        for label, variable in (("Lowercase letters", self.lower), ("Uppercase letters", self.upper),
                                ("Numbers", self.digits), ("Symbols", self.symbols)):
            tk.Checkbutton(options, text=label, variable=variable, bg="#f4f6fb",
                           activebackground="#f4f6fb", font=("Segoe UI", 10),
                           anchor="w", command=self.generate).pack(fill="x")

        self.memorable_options = tk.LabelFrame(frame, text="Passphrase options",
                                               font=("Segoe UI", 9, "bold"), bg="#f4f6fb",
                                               fg="#172033", padx=10, pady=7)
        self.capitalize_first = tk.BooleanVar(value=True)
        self.use_full_words = tk.BooleanVar(value=True)
        self.leetspeak = tk.BooleanVar(value=False)
        self.add_numbers = tk.BooleanVar(value=False)
        tk.Checkbutton(self.memorable_options, text="Capitalize the first letter",
                       variable=self.capitalize_first, bg="#f4f6fb",
                       activebackground="#f4f6fb", font=("Segoe UI", 10),
                       anchor="w", command=self.generate).pack(fill="x")
        tk.Checkbutton(self.memorable_options, text="Use full words",
                       variable=self.use_full_words, bg="#f4f6fb",
                       activebackground="#f4f6fb", font=("Segoe UI", 10),
                       anchor="w", command=self.generate).pack(fill="x")
        tk.Checkbutton(self.memorable_options, text="Use leetspeak",
                       variable=self.leetspeak, bg="#f4f6fb",
                       activebackground="#f4f6fb", font=("Segoe UI", 10),
                       anchor="w", command=self.generate).pack(fill="x")
        tk.Checkbutton(self.memorable_options, text="Add a random digit to the end of each word",
                       variable=self.add_numbers, bg="#f4f6fb",
                       activebackground="#f4f6fb", font=("Segoe UI", 10),
                       anchor="w", command=self.generate).pack(fill="x")
        self.word_count_controls = tk.LabelFrame(frame, text="Words per passphrase (4–16)",
                                                 font=("Segoe UI", 9, "bold"), bg="#f4f6fb",
                                                 fg="#172033", padx=10, pady=5)
        self.word_count = tk.IntVar(value=6)
        tk.Label(self.word_count_controls, textvariable=self.word_count, width=3,
                 font=("Segoe UI", 10), bg="#f4f6fb", fg="#172033").pack(anchor="e")
        tk.Scale(self.word_count_controls, from_=4, to=16, orient="horizontal",
                 variable=self.word_count, showvalue=False, resolution=1,
                 bg="#f4f6fb", highlightthickness=0, troughcolor="#d8deea").pack(fill="x")
        tk.Label(self.memorable_options, text="Word separator", font=("Segoe UI", 10, "bold"),
                 bg="#f4f6fb", fg="#172033").pack(anchor="w", pady=(8, 0))
        self.separator = tk.StringVar(value="-")
        for label, value in WORD_SEPARATOR_OPTIONS:
            tk.Radiobutton(self.memorable_options, text=label, variable=self.separator,
                           value=value, command=self.generate, bg="#f4f6fb",
                           activebackground="#f4f6fb", font=("Segoe UI", 10),
                           anchor="w").pack(fill="x")

        self.token_controls = tk.LabelFrame(
            frame, text="API token options", font=("Segoe UI", 9, "bold"),
            bg="#f4f6fb", fg="#172033", padx=10, pady=7)
        tk.Label(self.token_controls, text="Token size (bytes; 8 bits of entropy per byte)",
                 font=("Segoe UI", 10, "bold"), bg="#f4f6fb", fg="#172033").pack(anchor="w")
        self.token_bytes = tk.IntVar(value=32)
        self.token_bytes_value = tk.Label(
            self.token_controls, textvariable=self.token_bytes, width=4,
            font=("Segoe UI", 10), bg="#f4f6fb", fg="#172033")
        self.token_bytes_value.pack(anchor="e")
        tk.Scale(self.token_controls, from_=16, to=64, orient="horizontal",
                 variable=self.token_bytes, showvalue=False, resolution=1,
                 bg="#f4f6fb", highlightthickness=0, troughcolor="#d8deea").pack(fill="x")
        tk.Label(self.token_controls, text="Encoding", font=("Segoe UI", 10, "bold"),
                 bg="#f4f6fb", fg="#172033").pack(anchor="w", pady=(5, 0))
        self.token_encoding = tk.StringVar(value="urlsafe")
        for label, value in (("URL-safe Base64 (recommended)", "urlsafe"),
                             ("Hexadecimal", "hex")):
            tk.Radiobutton(self.token_controls, text=label, variable=self.token_encoding,
                           value=value, command=self.generate, bg="#f4f6fb",
                           activebackground="#f4f6fb", font=("Segoe UI", 10),
                           anchor="w").pack(fill="x")

        self.pin_controls = tk.LabelFrame(
            frame, text="PIN options", font=("Segoe UI", 9, "bold"),
            bg="#f4f6fb", fg="#172033", padx=10, pady=5)
        pin_header = tk.Frame(self.pin_controls, bg="#f4f6fb")
        pin_header.pack(fill="x")
        tk.Label(pin_header, text="PIN length (digits)", font=("Segoe UI", 10, "bold"),
                 bg="#f4f6fb", fg="#172033").pack(side="left")
        self.pin_length = tk.IntVar(value=6)
        tk.Label(pin_header, textvariable=self.pin_length, width=4,
                 font=("Segoe UI", 10), bg="#f4f6fb", fg="#172033").pack(side="right")
        tk.Scale(self.pin_controls, from_=3, to=12, orient="horizontal",
                 variable=self.pin_length, showvalue=False, resolution=1,
                 bg="#f4f6fb", highlightthickness=0, troughcolor="#d8deea").pack(fill="x")

        self.username_word_count_controls = tk.LabelFrame(
            frame, text="Words per username (1–5)", font=("Segoe UI", 9, "bold"),
            bg="#f4f6fb", fg="#172033", padx=10, pady=5)
        self.username_word_count = tk.IntVar(value=2)
        tk.Label(self.username_word_count_controls, textvariable=self.username_word_count,
                 width=3, font=("Segoe UI", 10), bg="#f4f6fb", fg="#172033").pack(anchor="e")
        tk.Scale(self.username_word_count_controls, from_=1, to=5, orient="horizontal",
                 variable=self.username_word_count, showvalue=False, resolution=1,
                 bg="#f4f6fb", highlightthickness=0, troughcolor="#d8deea").pack(fill="x")

        self.username_options = tk.LabelFrame(
            frame, text="Username style", font=("Segoe UI", 9, "bold"),
            bg="#f4f6fb", fg="#172033", padx=10, pady=7)
        self.username_adjectives = tk.BooleanVar(value=True)
        self.username_nouns = tk.BooleanVar(value=True)
        self.username_verbs = tk.BooleanVar(value=False)
        self.username_capitalize = tk.BooleanVar(value=True)
        self.username_leetspeak = tk.BooleanVar(value=False)
        for label, variable in (
            ("Adjectives", self.username_adjectives),
            ("Nouns", self.username_nouns),
            ("Verbs", self.username_verbs),
            ("Capitalize", self.username_capitalize),
            ("Leetspeak", self.username_leetspeak),
        ):
            tk.Checkbutton(self.username_options, text=label, variable=variable,
                           bg="#f4f6fb", activebackground="#f4f6fb",
                           font=("Segoe UI", 10), anchor="w",
                           command=self.generate).pack(fill="x")
        tk.Label(self.username_options, text="Word separator",
                 font=("Segoe UI", 10, "bold"), bg="#f4f6fb", fg="#172033").pack(
                     anchor="w", pady=(8, 0))
        self.username_separator = tk.StringVar(value="-")
        for label, value in (("No separator", ""), *WORD_SEPARATOR_OPTIONS):
            tk.Radiobutton(self.username_options, text=label, variable=self.username_separator,
                           value=value, command=self.generate, bg="#f4f6fb",
                           activebackground="#f4f6fb", font=("Segoe UI", 10),
                           anchor="w").pack(fill="x")

        self.random_number_controls = tk.LabelFrame(
            frame, text="Random number range", font=("Segoe UI", 9, "bold"),
            bg="#f4f6fb", fg="#172033", padx=10, pady=8)
        number_limits = tk.Frame(self.random_number_controls, bg="#f4f6fb")
        number_limits.pack(fill="x")
        self.random_minimum = tk.StringVar(value="1")
        self.random_maximum = tk.StringVar(value="100")
        for column, label, variable in (
            (0, "Minimum", self.random_minimum),
            (1, "Maximum", self.random_maximum),
        ):
            limit_field = tk.Frame(number_limits, bg="#f4f6fb")
            limit_field.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else 8, 0))
            limit_field.grid_columnconfigure(0, weight=1)
            tk.Label(limit_field, text=label, font=("Segoe UI", 10, "bold"),
                     bg="#f4f6fb", fg="#172033").grid(row=0, column=0, sticky="w")
            tk.Entry(limit_field, textvariable=variable, font=("Segoe UI", 10),
                     width=12).grid(row=1, column=0, sticky="ew", pady=(3, 0))
        number_limits.grid_columnconfigure(0, weight=1)
        number_limits.grid_columnconfigure(1, weight=1)
        tk.Button(self.random_number_controls, text="Generate number",
                  command=self.generate_random_number, font=("Segoe UI", 10, "bold"),
                  bg="#e5e9f2", fg="#172033", activebackground="#d5dbea",
                  relief="flat", padx=14, pady=7, cursor="hand2").pack(fill="x", pady=(10, 6))
        self.random_number_result = tk.StringVar(value="Your number will appear here.")
        tk.Label(self.random_number_controls, textvariable=self.random_number_result,
                 font=("Segoe UI", 14, "bold"), bg="#f4f6fb", fg="#172033",
                 anchor="center").pack(fill="x", pady=(2, 0))
        tk.Button(self.random_number_controls, text="Refresh generated values",
                  command=self.refresh_current_output, font=("Segoe UI", 10, "bold"),
                  bg="#e5e9f2", fg="#172033", activebackground="#d5dbea",
                  relief="flat", padx=12, pady=6, cursor="hand2").pack(fill="x", pady=(4, 6))
        history_header = tk.Frame(self.random_number_controls, bg="#f4f6fb")
        history_header.pack(fill="x", pady=(10, 3))
        tk.Label(history_header, text="History", font=("Segoe UI", 10, "bold"),
                 bg="#f4f6fb", fg="#172033").pack(side="left")
        tk.Button(history_header, text="Clear history", command=self.clear_random_number_history,
                  font=("Segoe UI", 8), bg="#e5e9f2", fg="#172033",
                  activebackground="#d5dbea", relief="flat", padx=7, pady=2,
                  cursor="hand2").pack(side="right")
        history_frame = tk.Frame(self.random_number_controls, bg="#f4f6fb")
        history_frame.pack(fill="x")
        history_scrollbar = tk.Scrollbar(history_frame, orient="vertical")
        self.random_number_history_list = tk.Listbox(
            history_frame, height=5, font=("Consolas", 9),
            yscrollcommand=history_scrollbar.set, exportselection=False)
        history_scrollbar.configure(command=self.random_number_history_list.yview)
        self.random_number_history_list.pack(side="left", fill="both", expand=True)
        history_scrollbar.pack(side="right", fill="y")
        self.random_number_history = []

        self.coin_toss_controls = tk.LabelFrame(
            frame, text="Coin toss", font=("Segoe UI", 9, "bold"),
            bg="#f4f6fb", fg="#172033", padx=10, pady=8)
        self.coin_toss_choice = tk.StringVar(value="Heads / Tails")
        for label in ("Heads / Tails", "Yes / No"):
            tk.Radiobutton(self.coin_toss_controls, text=label, variable=self.coin_toss_choice,
                           value=label, bg="#f4f6fb", activebackground="#f4f6fb",
                           font=("Segoe UI", 10), anchor="w").pack(fill="x")
        tk.Button(self.coin_toss_controls, text="Toss coin", command=self.toss_coin,
                  font=("Segoe UI", 10, "bold"), bg="#e5e9f2", fg="#172033",
                  activebackground="#d5dbea", relief="flat", padx=14, pady=7,
                  cursor="hand2").pack(fill="x", pady=(8, 6))
        self.coin_toss_result = tk.StringVar(value="Your result will appear here.")
        tk.Label(self.coin_toss_controls, textvariable=self.coin_toss_result,
                 font=("Segoe UI", 16, "bold"), bg="#f4f6fb", fg="#172033",
                 anchor="center").pack(fill="x", pady=(2, 0))
        tk.Button(self.coin_toss_controls, text="Refresh generated values",
                  command=self.refresh_current_output, font=("Segoe UI", 10, "bold"),
                  bg="#e5e9f2", fg="#172033", activebackground="#d5dbea",
                  relief="flat", padx=12, pady=6, cursor="hand2").pack(fill="x", pady=(4, 6))
        coin_history_header = tk.Frame(self.coin_toss_controls, bg="#f4f6fb")
        coin_history_header.pack(fill="x", pady=(10, 3))
        tk.Label(coin_history_header, text="History", font=("Segoe UI", 10, "bold"),
                 bg="#f4f6fb", fg="#172033").pack(side="left")
        tk.Button(coin_history_header, text="Clear history", command=self.clear_coin_toss_history,
                  font=("Segoe UI", 8), bg="#e5e9f2", fg="#172033",
                  activebackground="#d5dbea", relief="flat", padx=7, pady=2,
                  cursor="hand2").pack(side="right")
        coin_history_frame = tk.Frame(self.coin_toss_controls, bg="#f4f6fb")
        coin_history_frame.pack(fill="x")
        coin_history_scrollbar = tk.Scrollbar(coin_history_frame, orient="vertical")
        self.coin_toss_history_list = tk.Listbox(
            coin_history_frame, height=5, font=("Consolas", 9),
            yscrollcommand=coin_history_scrollbar.set, exportselection=False)
        coin_history_scrollbar.configure(command=self.coin_toss_history_list.yview)
        self.coin_toss_history_list.pack(side="left", fill="both", expand=True)
        coin_history_scrollbar.pack(side="right", fill="y")
        self.coin_toss_history = []

        self.dice_controls = tk.LabelFrame(
            frame, text="Dice roll", font=("Segoe UI", 9, "bold"),
            bg="#f4f6fb", fg="#172033", padx=10, pady=8)
        tk.Label(self.dice_controls, text="Die type", font=("Segoe UI", 10, "bold"),
                 bg="#f4f6fb", fg="#172033").pack(anchor="w")
        self.dice_sides = tk.IntVar(value=6)
        dice_types = tk.Frame(self.dice_controls, bg="#f4f6fb")
        dice_types.pack(fill="x")
        for sides in (4, 6, 8, 10, 12, 20):
            tk.Radiobutton(dice_types, text=f"d{sides}", variable=self.dice_sides,
                           value=sides, bg="#f4f6fb", activebackground="#f4f6fb",
                           font=("Segoe UI", 10)).pack(side="left", expand=True)
        tk.Label(self.dice_controls, text="Dice to roll", font=("Segoe UI", 10, "bold"),
                 bg="#f4f6fb", fg="#172033").pack(anchor="w", pady=(8, 0))
        self.dice_count = tk.IntVar(value=1)
        dice_counts = tk.Frame(self.dice_controls, bg="#f4f6fb")
        dice_counts.pack(fill="x")
        for count in (1, 2, 3):
            tk.Radiobutton(dice_counts, text=str(count), variable=self.dice_count,
                           value=count, bg="#f4f6fb", activebackground="#f4f6fb",
                           font=("Segoe UI", 10)).pack(side="left", expand=True)
        tk.Button(self.dice_controls, text="Roll dice", command=self.roll_dice,
                  font=("Segoe UI", 10, "bold"), bg="#e5e9f2", fg="#172033",
                  activebackground="#d5dbea", relief="flat", padx=14, pady=7,
                  cursor="hand2").pack(fill="x", pady=(8, 6))
        self.dice_result = tk.StringVar(value="Your roll will appear here.")
        tk.Label(self.dice_controls, textvariable=self.dice_result,
                 font=("Segoe UI", 14, "bold"), bg="#f4f6fb", fg="#172033",
                 anchor="center", justify="center").pack(fill="x", pady=(2, 0))
        tk.Button(self.dice_controls, text="Refresh generated values",
                  command=self.refresh_current_output, font=("Segoe UI", 10, "bold"),
                  bg="#e5e9f2", fg="#172033", activebackground="#d5dbea",
                  relief="flat", padx=12, pady=6, cursor="hand2").pack(fill="x", pady=(4, 6))
        dice_history_header = tk.Frame(self.dice_controls, bg="#f4f6fb")
        dice_history_header.pack(fill="x", pady=(10, 3))
        tk.Label(dice_history_header, text="History", font=("Segoe UI", 10, "bold"),
                 bg="#f4f6fb", fg="#172033").pack(side="left")
        tk.Button(dice_history_header, text="Clear history", command=self.clear_dice_history,
                  font=("Segoe UI", 8), bg="#e5e9f2", fg="#172033",
                  activebackground="#d5dbea", relief="flat", padx=7, pady=2,
                  cursor="hand2").pack(side="right")
        dice_history_frame = tk.Frame(self.dice_controls, bg="#f4f6fb")
        dice_history_frame.pack(fill="x")
        dice_history_scrollbar = tk.Scrollbar(dice_history_frame, orient="vertical")
        self.dice_history_list = tk.Listbox(
            dice_history_frame, height=5, font=("Consolas", 9),
            yscrollcommand=dice_history_scrollbar.set, exportselection=False)
        dice_history_scrollbar.configure(command=self.dice_history_list.yview)
        self.dice_history_list.pack(side="left", fill="both", expand=True)
        dice_history_scrollbar.pack(side="right", fill="y")
        self.dice_history = []

        self.casino_controls = tk.LabelFrame(
            frame, text="Casino", font=("Segoe UI", 9, "bold"),
            bg="#f4f6fb", fg="#172033", padx=10, pady=8)
        self.casino_play_style = tk.StringVar(value="ignorant")
        tk.Radiobutton(self.casino_controls, text="Ignorant (free play)",
                       variable=self.casino_play_style, value="ignorant",
                       command=self.update_casino_style, bg="#f4f6fb",
                       activebackground="#f4f6fb", font=("Segoe UI", 10),
                       anchor="w").pack(fill="x")
        tk.Radiobutton(self.casino_controls, text="Consequences (simulated money)",
                       variable=self.casino_play_style, value="consequences",
                       command=self.update_casino_style, bg="#f4f6fb",
                       activebackground="#f4f6fb", font=("Segoe UI", 10),
                       anchor="w").pack(fill="x")
        self.casino_cost_frame = tk.Frame(self.casino_controls, bg="#f4f6fb")
        tk.Label(self.casino_cost_frame, text="Cost per spin ($)",
                 font=("Segoe UI", 10, "bold"), bg="#f4f6fb", fg="#172033").pack(side="left")
        self.casino_spin_cost = tk.StringVar(value="10")
        tk.Entry(self.casino_cost_frame, textvariable=self.casino_spin_cost,
                 font=("Segoe UI", 10), width=10).pack(side="right")
        tk.Label(self.casino_cost_frame, text="Slot class (cost sets prize size)",
                 font=("Segoe UI", 9, "bold"), bg="#f4f6fb", fg="#172033").pack(
                     fill="x", anchor="w", pady=(8, 3))
        casino_presets = tk.Frame(self.casino_cost_frame, bg="#f4f6fb")
        casino_presets.pack(fill="x")
        self.casino_tier_name = tk.StringVar(value="Silver")
        self.casino_preset_buttons = {}
        for column, (tier_name, cost) in enumerate(
                (("Bronze", 1), ("Silver", 10), ("Gold", 50), ("Platinum", 100))):
            preset_button = tk.Button(
                casino_presets, text=f"{tier_name}\n${cost} / spin",
                command=lambda name=tier_name, amount=cost: self.select_casino_preset(name, amount),
                font=("Segoe UI", 9, "bold"), bg="#e5e9f2", fg="#172033",
                activebackground="#d5dbea", relief="flat", padx=4, pady=5,
                cursor="hand2")
            preset_button.grid(row=0, column=column, sticky="ew", padx=2)
            self.casino_preset_buttons[tier_name] = preset_button
            casino_presets.grid_columnconfigure(column, weight=1)
        self.casino_preset_guard = False
        self.casino_balance = 0
        self.casino_net_worth_card = tk.Frame(self.casino_controls, bg="#172033", padx=12, pady=9)
        self.casino_net_worth_card.pack(fill="x", pady=(8, 8))
        tk.Label(self.casino_net_worth_card, text="YOUR NET WORTH", font=("Segoe UI", 10, "bold"),
                 bg="#172033", fg="#d5dbea").pack()
        self.casino_balance_label = tk.StringVar(value="$0")
        tk.Label(self.casino_net_worth_card, textvariable=self.casino_balance_label,
                 font=("Segoe UI", 24, "bold"), bg="#172033", fg="#a7f06a",
                 anchor="center").pack(fill="x")
        self.casino_payout_text = tk.StringVar(value="")
        tk.Label(self.casino_controls, textvariable=self.casino_payout_text,
                 font=("Segoe UI", 9), bg="#f4f6fb", fg="#586174",
                 wraplength=360, justify="left").pack(fill="x", anchor="w")
        jackpot_frame = tk.LabelFrame(
            self.casino_controls, text="Jackpot wins — largest first",
            font=("Segoe UI", 10, "bold"), bg="#fff7df", fg="#805600",
            padx=8, pady=5, highlightbackground="#e6b84a", highlightthickness=1)
        jackpot_frame.pack(fill="x", pady=(8, 2))
        self.casino_jackpots_list = tk.Listbox(
            jackpot_frame, height=4, font=("Segoe UI", 10, "bold"),
            bg="#fff7df", fg="#674600", relief="flat", activestyle="none",
            exportselection=False)
        self.casino_jackpots_list.pack(fill="x", expand=True)
        self.casino_jackpots = []
        tk.Button(self.casino_controls, text="Roll slots", command=self.roll_casino,
                  font=("Segoe UI", 10, "bold"), bg="#e5e9f2", fg="#172033",
                  activebackground="#d5dbea", relief="flat", padx=14, pady=7,
                  cursor="hand2").pack(fill="x", pady=(8, 6))
        self.casino_result = tk.StringVar(value="Your symbols will appear here.")
        tk.Label(self.casino_controls, textvariable=self.casino_result,
                 font=("Segoe UI", 15, "bold"), bg="#f4f6fb", fg="#172033",
                 anchor="center", justify="center").pack(fill="x", pady=(2, 0))
        casino_history_header = tk.Frame(self.casino_controls, bg="#f4f6fb")
        casino_history_header.pack(fill="x", pady=(10, 3))
        tk.Label(casino_history_header, text="History", font=("Segoe UI", 10, "bold"),
                 bg="#f4f6fb", fg="#172033").pack(side="left")
        tk.Button(casino_history_header, text="Clear history", command=self.clear_casino_history,
                  font=("Segoe UI", 8), bg="#e5e9f2", fg="#172033",
                  activebackground="#d5dbea", relief="flat", padx=7, pady=2,
                  cursor="hand2").pack(side="right")
        casino_history_frame = tk.Frame(self.casino_controls, bg="#f4f6fb")
        casino_history_frame.pack(fill="x")
        casino_history_scrollbar = tk.Scrollbar(casino_history_frame, orient="vertical")
        self.casino_history_list = tk.Listbox(
            casino_history_frame, height=5, font=("Segoe UI", 10),
            yscrollcommand=casino_history_scrollbar.set, exportselection=False)
        casino_history_scrollbar.configure(command=self.casino_history_list.yview)
        self.casino_history_list.pack(side="left", fill="both", expand=True)
        casino_history_scrollbar.pack(side="right", fill="y")
        self.casino_history = []
        self.casino_spin_cost.trace_add("write", lambda *_: self.on_casino_cost_changed())
        self.on_casino_cost_changed()
        self.dice_cumulative_total = 0

        self.tarot_controls = tk.LabelFrame(
            frame, text="Tarot draw", font=("Segoe UI", 9, "bold"),
            bg="#f4f6fb", fg="#172033", padx=10, pady=8)
        tk.Label(self.tarot_controls,
                 text="Choose a one-card draw, a beginner-friendly three-card spread, or a 10-card Celtic Cross. Yes/no results are reflective, not predictions.",
                 font=("Segoe UI", 9), bg="#f4f6fb", fg="#586174",
                 wraplength=360, justify="left").pack(fill="x", anchor="w", pady=(0, 8))
        self.tarot_spread_mode = tk.StringVar(value="one")
        tarot_mode_options = tk.Frame(self.tarot_controls, bg="#f4f6fb")
        tarot_mode_options.pack(fill="x", pady=(0, 5))
        tk.Radiobutton(tarot_mode_options, text="One card", variable=self.tarot_spread_mode,
                       value="one", command=self.update_tarot_spread_mode,
                       bg="#f4f6fb", activebackground="#f4f6fb",
                       font=("Segoe UI", 10)).pack(side="left")
        tk.Radiobutton(tarot_mode_options, text="Three-card spread", variable=self.tarot_spread_mode,
                       value="three", command=self.update_tarot_spread_mode,
                       bg="#f4f6fb", activebackground="#f4f6fb",
                       font=("Segoe UI", 10)).pack(side="left", padx=(12, 0))
        tk.Radiobutton(tarot_mode_options, text="Celtic Cross", variable=self.tarot_spread_mode,
                       value="celtic", command=self.update_tarot_spread_mode,
                       bg="#f4f6fb", activebackground="#f4f6fb",
                       font=("Segoe UI", 10)).pack(side="left", padx=(12, 0))
        self.tarot_spread_choice = tk.StringVar(value="Past — Present — Future")
        self.tarot_spread_picker = ttk.Combobox(
            self.tarot_controls, textvariable=self.tarot_spread_choice, state="readonly",
            values=("Past — Present — Future", "Situation — Action — Outcome",
                    "Mind — Body — Spirit", "Problem — Advice — Solution"),
            font=("Segoe UI", 10))
        self.tarot_spread_picker.pack(fill="x", pady=(0, 6))
        self.tarot_spread_picker.pack_forget()
        self.tarot_spread_picker.bind(
            "<<ComboboxSelected>>", lambda _event: self.update_tarot_spread_mode())
        self.three_card_help = tk.Label(
            self.tarot_controls, text="", font=("Segoe UI", 9),
            bg="#eef1f8", fg="#273247", justify="left", anchor="w",
            wraplength=360, padx=9, pady=7, relief="solid", bd=1)
        self.celtic_help = tk.Label(
            self.tarot_controls,
            text=(
                "How to read the Celtic Cross (10 cards)\n"
                "1 Present — the heart of the question.\n"
                "2 Challenge — the main obstacle or tension crossing it.\n"
                "3 Past — recent influences that led here.\n"
                "4 Future — the near-term direction.\n"
                "5 Above — conscious aims or what you want.\n"
                "6 Below — the underlying foundation or less-visible influence.\n"
                "7 Advice — your approach or a useful response.\n"
                "8 External influences — people and circumstances around you.\n"
                "9 Hopes and fears — expectations that may shape your view.\n"
                "10 Outcome — where things may lead if current influences continue.\n\n"
                "Read cards 1 and 2 together first, then connect the context cards (3–6) "
                "with the staff (7–10). Look for patterns across the spread; the outcome "
                "is a possible direction, not a fixed prediction. Position labels vary "
                "between Celtic Cross versions."
            ),
            font=("Segoe UI", 9), bg="#eef1f8", fg="#273247",
            justify="left", anchor="w", wraplength=360, padx=9, pady=7,
            relief="solid", bd=1)
        self.tarot_draw_button = tk.Button(
            self.tarot_controls, text="Draw a tarot card", command=self.draw_current_tarot,
            font=("Segoe UI", 10, "bold"), bg="#e5e9f2", fg="#172033",
            activebackground="#d5dbea", relief="flat", padx=14, pady=7,
            cursor="hand2")
        self.tarot_draw_button.pack(fill="x", pady=(0, 6))
        self.tarot_single_result = tk.Frame(self.tarot_controls, bg="#f4f6fb")
        self.tarot_image_label = tk.Label(self.tarot_single_result, bg="#f4f6fb")
        self.tarot_image_label.pack(fill="x", pady=(3, 6))
        self.tarot_card_name = tk.StringVar(value="Your card will appear here")
        tk.Label(self.tarot_single_result, textvariable=self.tarot_card_name,
                 font=("Segoe UI", 17, "bold"), bg="#f4f6fb", fg="#172033",
                 anchor="center", justify="center", wraplength=360).pack(fill="x", pady=(2, 5))
        self.tarot_orientation = tk.StringVar(value="")
        tk.Label(self.tarot_single_result, textvariable=self.tarot_orientation,
                 font=("Segoe UI", 10, "bold"), bg="#f4f6fb", fg="#586174",
                 anchor="center").pack(fill="x")
        self.tarot_description = tk.StringVar(value="")
        tk.Label(self.tarot_single_result, textvariable=self.tarot_description,
                 font=("Segoe UI", 10), bg="#f4f6fb", fg="#172033",
                 anchor="center", justify="center", wraplength=360).pack(fill="x", pady=(4, 8))
        tarot_answer_card = tk.Frame(self.tarot_single_result, bg="#172033", padx=10, pady=6)
        tarot_answer_card.pack(fill="x", pady=(0, 8))
        tk.Label(tarot_answer_card, text="YES / NO LEANING", font=("Segoe UI", 9, "bold"),
                 bg="#172033", fg="#d5dbea").pack()
        self.tarot_answer = tk.StringVar(value="—")
        self.tarot_answer_label = tk.Label(
            tarot_answer_card, textvariable=self.tarot_answer,
            font=("Segoe UI", 21, "bold"), bg="#172033", fg="#a7f06a")
        self.tarot_answer_label.pack()
        self.tarot_single_result.pack(fill="x", pady=(2, 0))
        self.tarot_spread_results = tk.Frame(self.tarot_controls, bg="#f4f6fb")
        self.tarot_spread_results.pack_forget()
        self.tarot_spread_positions = {
            "Past — Present — Future": ("Past", "Present", "Future"),
            "Situation — Action — Outcome": ("Situation", "Action", "Outcome"),
            "Mind — Body — Spirit": ("Mind", "Body", "Spirit"),
            "Problem — Advice — Solution": ("Problem", "Advice", "Solution"),
            "Celtic Cross — 10 cards": (
                "1 · Present", "2 · Challenge", "3 · Past", "4 · Future",
                "5 · Above / conscious aim", "6 · Below / foundation",
                "7 · Advice", "8 · External influences",
                "9 · Hopes and fears", "10 · Outcome",
            ),
        }
        self.tarot_spread_cards = []
        for card_index in range(10):
            initial_positions = self.tarot_spread_positions[self.tarot_spread_choice.get()]
            initial_position = (initial_positions[card_index]
                                if card_index < len(initial_positions)
                                else f"Card {card_index + 1}")
            spread_card = tk.LabelFrame(
                self.tarot_spread_results, text=initial_position,
                font=("Segoe UI", 9, "bold"), bg="#f4f6fb", fg="#172033",
                padx=7, pady=5)
            spread_card.pack(fill="x", pady=(3, 5))
            spread_content = tk.Frame(spread_card, bg="#f4f6fb")
            spread_content.pack(fill="x")
            spread_image = tk.Label(spread_content, bg="#f4f6fb", width=110)
            spread_image.pack(side="left", padx=(0, 8))
            spread_text = tk.Frame(spread_content, bg="#f4f6fb")
            spread_text.pack(side="left", fill="x", expand=True)
            card_name_var = tk.StringVar(value="")
            tk.Label(spread_text, textvariable=card_name_var,
                     font=("Segoe UI", 11, "bold"), bg="#f4f6fb", fg="#172033",
                     anchor="w", justify="left", wraplength=220).pack(fill="x")
            orientation_var = tk.StringVar(value="")
            tk.Label(spread_text, textvariable=orientation_var,
                     font=("Segoe UI", 9, "bold"), bg="#f4f6fb", fg="#586174",
                     anchor="w").pack(fill="x", pady=(1, 3))
            description_var = tk.StringVar(value="")
            tk.Label(spread_text, textvariable=description_var,
                     font=("Segoe UI", 9), bg="#f4f6fb", fg="#172033",
                     anchor="w", justify="left", wraplength=220).pack(fill="x")
            answer_var = tk.StringVar(value="")
            answer_label = tk.Label(spread_text, textvariable=answer_var,
                     font=("Segoe UI", 10, "bold"), bg="#f4f6fb", fg="#172033",
                     anchor="w")
            answer_label.pack(fill="x", pady=(3, 0))
            self.tarot_spread_cards.append({
                "frame": spread_card, "image": spread_image,
                "name": card_name_var, "orientation": orientation_var,
                "description": description_var, "answer": answer_var,
                "answer_label": answer_label, "image_ref": None,
            })
            if card_index >= 3:
                spread_card.pack_forget()
        self.tarot_history_header = tk.Frame(self.tarot_controls, bg="#f4f6fb")
        self.tarot_history_header.pack(fill="x", pady=(5, 3))
        tk.Label(self.tarot_history_header, text="History", font=("Segoe UI", 10, "bold"),
                 bg="#f4f6fb", fg="#172033").pack(side="left")
        tk.Button(self.tarot_history_header, text="Clear history", command=self.clear_tarot_history,
                  font=("Segoe UI", 8), bg="#e5e9f2", fg="#172033",
                  activebackground="#d5dbea", relief="flat", padx=7, pady=2,
                  cursor="hand2").pack(side="right")
        tarot_history_frame = tk.Frame(self.tarot_controls, bg="#f4f6fb")
        tarot_history_frame.pack(fill="x")
        tarot_history_scrollbar = tk.Scrollbar(tarot_history_frame, orient="vertical")
        self.tarot_history_list = tk.Listbox(
            tarot_history_frame, height=5, font=("Segoe UI", 9),
            yscrollcommand=tarot_history_scrollbar.set, exportselection=False)
        tarot_history_scrollbar.configure(command=self.tarot_history_list.yview)
        self.tarot_history_list.pack(side="left", fill="both", expand=True)
        tarot_history_scrollbar.pack(side="right", fill="y")
        self.tarot_history = []

        # Each password gets its own row and copy button.
        self.password_rows = tk.Frame(frame, bg="#f4f6fb")
        self.password_rows.pack(fill="x", pady=(0, 12))

        buttons = tk.Frame(frame, bg="#f4f6fb")
        buttons.pack(fill="x")
        self.copy_all_button = tk.Button(
            buttons, text="Copy all", command=self.copy_all, font=("Segoe UI", 10),
            bg="#e5e9f2", fg="#172033", activebackground="#d5dbea",
            relief="flat", padx=14, pady=8, cursor="hand2")

        # Independent checker for passwords the user already has. It does not
        # modify generation settings or send the entered value anywhere.
        self.checker = tk.LabelFrame(
            frame, text="Check an existing password", font=("Segoe UI", 9, "bold"),
            bg="#f4f6fb", fg="#172033", padx=10, pady=7)
        self.checker.pack(fill="x", pady=(0, 12), before=mode_frame)
        checker_input = tk.Frame(self.checker, bg="#f4f6fb")
        checker_input.pack(fill="x")
        self.check_password = tk.StringVar()
        self.check_entry = tk.Entry(
            checker_input, textvariable=self.check_password, show="•",
            font=("Consolas", 11), relief="solid", bd=1)
        self.check_entry.pack(side="left", fill="x", expand=True, ipady=4)
        self.show_check_password = tk.BooleanVar(value=False)
        tk.Checkbutton(
            checker_input, text="Show", variable=self.show_check_password,
            command=self.toggle_check_password, bg="#f4f6fb",
            activebackground="#f4f6fb", font=("Segoe UI", 9)).pack(side="left", padx=(8, 0))
        tk.Button(
            checker_input, text="Clear", command=lambda: self.check_password.set(""),
            font=("Segoe UI", 9), bg="#e5e9f2", fg="#172033",
            activebackground="#d5dbea", relief="flat", padx=8, pady=3,
            cursor="hand2").pack(side="left", padx=(5, 0))
        self.breach_check_button = tk.Button(
            checker_input, text="Check breach database", command=self.check_pwned_password,
            font=("Segoe UI", 9), bg="#e5e9f2", fg="#172033",
            activebackground="#d5dbea", relief="flat", padx=8, pady=3,
            cursor="hand2")
        self.breach_check_button.pack(side="left", padx=(5, 0))
        self.check_results = tk.Frame(self.checker, bg="#f4f6fb")
        self.check_results.pack(fill="x", pady=(7, 0))
        self.check_result = tk.StringVar(value="Type or paste a password to check it.")
        tk.Label(
            self.checker,
            text="Optional online check (only when clicked): the password stays on this device. "
                 "The app sends Have I Been Pwned only the first 5 characters of its SHA-1 hash, "
                 "then compares the returned hash suffixes locally. This reduces exposure, "
                 "but network providers can still see the request and its hash prefix.",
            justify="left", anchor="w", wraplength=700, font=("Segoe UI", 8),
            bg="#f4f6fb", fg="#586174").pack(fill="x", pady=(5, 0))
        self.breach_status = tk.StringVar(value="Breach check has not been run.")
        tk.Label(self.checker, textvariable=self.breach_status, justify="left",
                 anchor="w", wraplength=700, font=("Segoe UI", 9, "bold"),
                 bg="#f4f6fb", fg="#586174").pack(fill="x", pady=(3, 0))

        self.length.trace_add("write", lambda *_: self.generate())
        self.count.trace_add("write", lambda *_: self.generate())
        self.word_count.trace_add("write", lambda *_: self.generate())
        self.username_word_count.trace_add("write", lambda *_: self.generate())
        self.token_bytes.trace_add("write", lambda *_: self.generate())
        self.pin_length.trace_add("write", lambda *_: self.generate())
        self.check_password.trace_add("write", lambda *_: self.update_password_check())
        self.generate()

    def toggle_check_password(self):
        self.check_entry.configure(show="" if self.show_check_password.get() else "•")

    def update_password_check(self):
        password = self.check_password.get()
        if hasattr(self, "breach_status"):
            self.breach_status.set("Breach check has not been run for this password.")
        for child in self.check_results.winfo_children():
            child.destroy()
        if not password:
            tk.Label(self.check_results, text="Type or paste a password to check it.",
                     anchor="w", font=("Segoe UI", 9), bg="#f4f6fb",
                     fg="#586174").pack(fill="x")
            return

        generated_entropy = getattr(self, "generated_password_entropy", {}).get(password)
        if generated_entropy is not None:
            self.add_check_estimate(
                "Generator entropy estimate (matches a currently generated password)",
                f"~{generated_entropy} bits", "#586174")
        else:
            character_entropy = self.character_set_entropy_estimate(password)
            self.add_check_estimate(
                "Character-set entropy estimate (assumes random characters)",
                f"~{character_entropy:.1f} bits", "#586174")

        if zxcvbn is not None:
            try:
                result = zxcvbn(password, max_length=max(72, len(password)))
                score = result["score"]
                rating = ("Worst", "Weak", "Fair", "Good", "Strong")[score]
                guesses_log10 = float(result.get("guesses_log10", math.log10(max(1, result["guesses"]))))
                entropy_bits = guesses_log10 * math.log2(10)
                average_guesses_log10 = max(0.0, guesses_log10 - math.log10(2))
                slow = self.format_duration_log10(average_guesses_log10 - math.log10(CRACK_GUESSES_PER_SECOND))
                fast = self.format_duration_log10(average_guesses_log10 - math.log10(FAST_HASH_GUESSES_PER_SECOND))
                online = self.format_duration_log10(
                    average_guesses_log10 + math.log10(3600 / ONLINE_GUESSES_PER_HOUR))
                bar_score = score * 25
                color = self.strength_bar_color(bar_score)
                self.add_check_estimate(
                    "zxcvbn estimate (log₂ of estimated guesses)",
                    f"~{entropy_bits:.1f} bits", color)
                if generated_entropy is not None:
                    self.add_check_note(
                        "The generator estimate reflects the random choices used to create it; "
                        "zxcvbn estimates guessability from patterns it recognizes in the text.")
                self.add_check_strength(rating, f"zxcvbn score: {score}/4", bar_score, color)
                self.add_check_estimate("Estimated crack time (zxcvbn guess estimate):")
                self.add_check_estimate("Offline slow hash (~10K guesses/s)", slow, color)
                self.add_check_estimate("Offline fast hash (~10B guesses/s)", fast, color)
                self.add_check_estimate("Online throttled (~100 guesses/hour)", online, color)
                self.add_check_note(
                    "Entropy is an approximate log₂ guess count from zxcvbn, not a guarantee. "
                    "Checked locally on this device. Times depend on the attack and password hash.")
            except (KeyError, TypeError, ValueError, OverflowError) as error:
                self.add_check_note(f"Could not assess this value with zxcvbn: {error}")
        else:
            bits = self.character_set_entropy_estimate(password)
            rating = self.entropy_strength_rating(bits)
            bar_score = max(0, min(100, int(round(bits))))
            color = self.strength_bar_color(bar_score)
            self.add_check_estimate(
                "zxcvbn guess-based entropy estimate", "unavailable (zxcvbn not installed)")
            self.add_check_strength(rating, "Fallback strength", bar_score, color)
            self.add_check_estimate("Estimated crack time (character-set entropy; average guesses):")
            self.add_check_estimate("Offline slow hash (~10K guesses/s)",
                                    self.entropy_crack_time(int(round(bits)), CRACK_GUESSES_PER_SECOND), color)
            self.add_check_estimate("Offline fast hash (~10B guesses/s)",
                                    self.entropy_crack_time(int(round(bits)), FAST_HASH_GUESSES_PER_SECOND), color)
            self.add_check_estimate("Online throttled (~100 guesses/hour)",
                                    self.entropy_crack_time(int(round(bits)), ONLINE_GUESSES_PER_HOUR, 3600), color)
            self.add_check_note("Fallback assumes random character selection and may overestimate human-chosen passwords. "
                                "Install optional zxcvbn for pattern-aware checking. Checked locally on this device.")

    def check_pwned_password(self):
        password = self.check_password.get()
        if not password:
            self.breach_status.set("Enter a password first, then choose Check breach database.")
            return

        self.breach_check_button.configure(state="disabled")
        self.breach_status.set("Checking Have I Been Pwned…")
        threading.Thread(target=self._query_pwned_password, args=(password,), daemon=True).start()

    def _query_pwned_password(self, password):
        full_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = full_hash[:5], full_hash[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        request = urllib.request.Request(
            url, headers={"User-Agent": "PasswordSecurityToolkit/1.0", "Add-Padding": "true"})
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                lines = response.read().decode("ascii", errors="replace").splitlines()
            occurrences = 0
            for line in lines:
                returned_suffix, separator, count = line.strip().partition(":")
                if separator and returned_suffix.upper() == suffix:
                    occurrences = int(count)
                    break
            self.root.after(0, self._show_pwned_result, password, occurrences, None)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as error:
            self.root.after(0, self._show_pwned_result, password, None, str(error))

    def _show_pwned_result(self, checked_password, occurrences, error):
        self.breach_check_button.configure(state="normal")
        if self.check_password.get() != checked_password:
            return
        if error is not None:
            self.breach_status.set(f"Breach check failed: {error}")
        elif occurrences:
            self.breach_status.set(
                f"Found in Have I Been Pwned {occurrences:,} time(s). Do not use this password.")
        else:
            self.breach_status.set(
                "Not found in the Pwned Passwords database. This does not guarantee it has never been exposed.")

    def add_check_strength(self, rating, detail, score, color):
        line = tk.Frame(self.check_results, bg="#f4f6fb")
        line.pack(fill="x", anchor="w")
        tk.Label(line, text="Strength: ", font=("Segoe UI", 9),
                 bg="#f4f6fb", fg="#586174").pack(side="left")
        tk.Label(line, text=rating, font=("Segoe UI", 9, "bold"),
                 bg="#f4f6fb", fg=color).pack(side="left")
        tk.Label(line, text=f"  ·  {detail}", font=("Segoe UI", 9),
                 bg="#f4f6fb", fg="#586174").pack(side="left")
        style = f"CheckStrength{score}.Horizontal.TProgressbar"
        self.progress_style.configure(style, background=color, troughcolor="#e5e9f2")
        ttk.Progressbar(self.check_results, maximum=100, value=score, mode="determinate",
                        style=style).pack(fill="x", pady=(2, 6))

    def add_check_estimate(self, label, value=None, color="#586174"):
        line = tk.Frame(self.check_results, bg="#f4f6fb")
        line.pack(fill="x", anchor="w")
        tk.Label(line, text=label + (": " if value is not None else ""),
                 font=("Segoe UI", 9), bg="#f4f6fb", fg="#586174",
                 anchor="w").pack(side="left")
        if value is not None:
            tk.Label(line, text=value, font=("Segoe UI", 9, "bold"),
                     bg="#f4f6fb", fg=color, anchor="w").pack(side="left")

    def add_check_note(self, text):
        tk.Label(self.check_results, text=text, justify="left", anchor="w",
                 wraplength=700, font=("Segoe UI", 8), bg="#f4f6fb",
                 fg="#586174").pack(fill="x", pady=(4, 0))

    @staticmethod
    def format_duration_log10(seconds_log10):
        if seconds_log10 < 0:
            return "under 1 second"
        if seconds_log10 < math.log10(60):
            seconds = max(1, int(10 ** seconds_log10))
            return f"about {seconds} second{'s' if seconds != 1 else ''}"
        if seconds_log10 < math.log10(3600):
            return f"about {int(10 ** (seconds_log10 - math.log10(60)))} minutes"
        if seconds_log10 < math.log10(86400):
            return f"about {int(10 ** (seconds_log10 - math.log10(3600)))} hours"
        if seconds_log10 < math.log10(365 * 86400):
            return f"about {int(10 ** (seconds_log10 - math.log10(86400)))} days"
        years_log10 = seconds_log10 - math.log10(365 * 86400)
        if years_log10 < 3:
            return f"about {int(10 ** years_log10):,} years"
        return f"about 10^{years_log10:.0f} years"

    def update_mode(self):
        self.coin_toss_controls.pack_forget()
        self.dice_controls.pack_forget()
        self.casino_controls.pack_forget()
        self.tarot_controls.pack_forget()
        if self.mode.get() == "memorable":
            self.settings.pack_forget()
            self.options.pack_forget()
            self.token_controls.pack_forget()
            self.pin_controls.pack_forget()
            self.username_word_count_controls.pack_forget()
            self.username_options.pack_forget()
            self.random_number_controls.pack_forget()
            self.generation_controls.pack_forget()
            self.word_count_controls.pack(fill="x", pady=(0, 12), before=self.password_rows)
            self.generation_controls.pack(fill="x", pady=(0, 12), before=self.password_rows)
            self.memorable_options.pack(fill="x", pady=(0, 12), before=self.password_rows)
        elif self.mode.get() == "token":
            self.settings.pack_forget()
            self.options.pack_forget()
            self.word_count_controls.pack_forget()
            self.memorable_options.pack_forget()
            self.pin_controls.pack_forget()
            self.username_word_count_controls.pack_forget()
            self.username_options.pack_forget()
            self.random_number_controls.pack_forget()
            self.token_controls.pack(fill="x", pady=(0, 12), before=self.password_rows)
            self.generation_controls.pack(fill="x", pady=(0, 12), before=self.password_rows)
        elif self.mode.get() == "pin":
            self.settings.pack_forget()
            self.options.pack_forget()
            self.word_count_controls.pack_forget()
            self.memorable_options.pack_forget()
            self.token_controls.pack_forget()
            self.username_word_count_controls.pack_forget()
            self.username_options.pack_forget()
            self.random_number_controls.pack_forget()
            self.pin_controls.pack(fill="x", pady=(0, 12), before=self.password_rows)
            self.generation_controls.pack(fill="x", pady=(0, 12), before=self.password_rows)
        elif self.mode.get() == "username":
            self.settings.pack_forget()
            self.options.pack_forget()
            self.word_count_controls.pack_forget()
            self.memorable_options.pack_forget()
            self.token_controls.pack_forget()
            self.pin_controls.pack_forget()
            self.username_word_count_controls.pack(fill="x", pady=(0, 12), before=self.password_rows)
            self.generation_controls.pack(fill="x", pady=(0, 12), before=self.password_rows)
            self.username_options.pack(fill="x", pady=(0, 12), before=self.password_rows)
        elif self.mode.get() == "random_number":
            self.settings.pack_forget()
            self.options.pack_forget()
            self.word_count_controls.pack_forget()
            self.memorable_options.pack_forget()
            self.token_controls.pack_forget()
            self.pin_controls.pack_forget()
            self.username_word_count_controls.pack_forget()
            self.username_options.pack_forget()
            self.generation_controls.pack_forget()
            self.random_number_controls.pack(fill="x", pady=(0, 12), before=self.password_rows)
        elif self.mode.get() == "coin_toss":
            self.settings.pack_forget()
            self.options.pack_forget()
            self.word_count_controls.pack_forget()
            self.memorable_options.pack_forget()
            self.token_controls.pack_forget()
            self.pin_controls.pack_forget()
            self.username_word_count_controls.pack_forget()
            self.username_options.pack_forget()
            self.random_number_controls.pack_forget()
            self.generation_controls.pack_forget()
            self.coin_toss_controls.pack(fill="x", pady=(0, 12), before=self.password_rows)
        elif self.mode.get() == "dice_roll":
            self.settings.pack_forget()
            self.options.pack_forget()
            self.word_count_controls.pack_forget()
            self.memorable_options.pack_forget()
            self.token_controls.pack_forget()
            self.pin_controls.pack_forget()
            self.username_word_count_controls.pack_forget()
            self.username_options.pack_forget()
            self.random_number_controls.pack_forget()
            self.generation_controls.pack_forget()
            self.dice_controls.pack(fill="x", pady=(0, 12), before=self.password_rows)
        elif self.mode.get() == "casino":
            self.settings.pack_forget()
            self.options.pack_forget()
            self.word_count_controls.pack_forget()
            self.memorable_options.pack_forget()
            self.token_controls.pack_forget()
            self.pin_controls.pack_forget()
            self.username_word_count_controls.pack_forget()
            self.username_options.pack_forget()
            self.random_number_controls.pack_forget()
            self.generation_controls.pack_forget()
            self.casino_controls.pack(fill="x", pady=(0, 12), before=self.password_rows)
        elif self.mode.get() == "tarot":
            self.settings.pack_forget()
            self.options.pack_forget()
            self.word_count_controls.pack_forget()
            self.memorable_options.pack_forget()
            self.token_controls.pack_forget()
            self.pin_controls.pack_forget()
            self.username_word_count_controls.pack_forget()
            self.username_options.pack_forget()
            self.random_number_controls.pack_forget()
            self.generation_controls.pack_forget()
            self.tarot_controls.pack(fill="x", pady=(0, 12), before=self.password_rows)
        else:
            self.word_count_controls.pack_forget()
            self.memorable_options.pack_forget()
            self.token_controls.pack_forget()
            self.pin_controls.pack_forget()
            self.username_word_count_controls.pack_forget()
            self.username_options.pack_forget()
            self.random_number_controls.pack_forget()
            self.settings.pack(fill="x", pady=(0, 12), before=self.password_rows)
            self.standard_controls.grid()
            self.options.pack(fill="x", pady=(0, 14), before=self.password_rows)
            self.generation_controls.pack(fill="x", pady=(0, 12), before=self.options)
        self.generate()

    def generate(self):
        if self.mode.get() in ("random_number", "coin_toss", "dice_roll", "casino", "tarot"):
            self.copy_all_button.pack_forget()
            for child in self.password_rows.winfo_children():
                child.destroy()
            self.generated_password_entropy = {}
            return

        try:
            count = self.count.get()
            if not 1 <= count <= MAX_PASSWORDS:
                raise ValueError(f"Choose a number from 1 to {MAX_PASSWORDS}.")
            if count > 1:
                self.copy_all_button.pack(side="left", expand=True, fill="x", padx=(5, 0))
            else:
                self.copy_all_button.pack_forget()
            if self.mode.get() == "memorable":
                passwords = [self.make_memorable_password() for _ in range(count)]
            elif self.mode.get() == "username":
                passwords = [self.make_username() for _ in range(count)]
            elif self.mode.get() == "token":
                passwords = [self.make_api_token() for _ in range(count)]
            elif self.mode.get() == "pin":
                passwords = [self.make_pin() for _ in range(count)]
            else:
                passwords = [
                    make_password(self.length.get(), self.lower.get(), self.upper.get(),
                                  self.digits.get(), self.symbols.get())
                    for _ in range(count)
                ]
        except (ValueError, tk.TclError) as error:
            messagebox.showerror("Invalid settings", str(error))
            return

        # Retain the generator's estimate to compare it with the independent
        # checker estimate when a generated value is pasted into the input.
        self.generated_password_entropy = {
            password: self.entropy_estimate(password) for password in passwords
        }

        for child in self.password_rows.winfo_children():
            child.destroy()

        for index, password in enumerate(passwords, start=1):
            row = tk.Frame(self.password_rows, bg="white", padx=8, pady=5,
                           highlightbackground="#d8deea", highlightthickness=1)
            row.pack(fill="x", pady=3)
            row.grid_columnconfigure(2, weight=1)
            tk.Label(row, text=f"{index}.", font=("Segoe UI", 9),
                     bg="white", fg="#586174", width=3, anchor="w").grid(
                         row=0, column=0, rowspan=7, sticky="w", padx=(0, 5))
            tk.Button(row, text="Copy", command=lambda value=password: self.copy_password(value),
                      font=("Segoe UI", 9), bg="#e5e9f2", fg="#172033",
                      activebackground="#d5dbea", relief="flat", padx=10, pady=3,
                      cursor="hand2").grid(row=0, column=1, rowspan=7, sticky="ns", padx=(0, 8))
            password_entry = tk.Entry(row, font=("Consolas", 12), width=24,
                                      readonlybackground="white", fg="#172033",
                                      relief="flat", bd=0)
            password_entry.insert(0, password)
            password_entry.configure(state="readonly")
            password_entry.grid(row=0, column=2, sticky="ew")
            horizontal_scrollbar = tk.Scrollbar(row, orient="horizontal",
                                                command=password_entry.xview)
            horizontal_scrollbar.grid(row=1, column=2, sticky="ew", pady=(2, 0))
            horizontal_scrollbar.grid_remove()
            zxcvbn_rating, zxcvbn_score, _zxcvbn_crack_time, zxcvbn_entropy_bits = self.password_strength(password)
            entropy_bits = self.entropy_estimate(password)
            tk.Label(row, text=f"Generator entropy estimate: ~{entropy_bits} bits",
                     font=("Segoe UI", 9), bg="white", fg="#586174").grid(
                         row=2, column=2, sticky="w", pady=(4, 1))
            if zxcvbn_entropy_bits is None:
                zxcvbn_bits_text = "zxcvbn guess-based estimate: unavailable (zxcvbn not installed)"
            else:
                zxcvbn_bits_text = f"zxcvbn estimate (log₂ guesses): ~{zxcvbn_entropy_bits:.1f} bits"
            tk.Label(row, text=zxcvbn_bits_text,
                     font=("Segoe UI", 9), bg="white", fg="#586174").grid(
                         row=3, column=2, sticky="w", pady=(1, 1))
            strength_name = self.entropy_strength_rating(entropy_bits)
            strength_score = max(0, min(100, entropy_bits))
            rating_prefix = "Entropy strength: "
            if zxcvbn_score is None:
                unavailable_note = " (zxcvbn not installed)"
            else:
                unavailable_note = ""

            strength_color = self.strength_bar_color(strength_score)
            strength_line = tk.Frame(row, bg="white")
            strength_line.grid(row=4, column=2, sticky="w", pady=(2, 1))
            tk.Label(strength_line, text=rating_prefix, font=("Segoe UI", 9),
                     bg="white", fg="#586174").pack(side="left")
            tk.Label(strength_line, text=strength_name, font=("Segoe UI", 9, "bold"),
                     bg="white", fg=strength_color).pack(side="left")
            if zxcvbn_score is not None:
                tk.Label(strength_line,
                         text=f"  ·  zxcvbn: {zxcvbn_rating} ({zxcvbn_score}/4)",
                         font=("Segoe UI", 9), bg="white", fg="#586174").pack(side="left")
            if unavailable_note:
                tk.Label(strength_line, text=unavailable_note, font=("Segoe UI", 9),
                         bg="white", fg="#586174").pack(side="left")

            strength_style = f"Strength{strength_score}.Horizontal.TProgressbar"
            self.progress_style.configure(
                strength_style, background=strength_color,
                troughcolor="#e5e9f2"
            )
            ttk.Progressbar(row, maximum=100, value=strength_score,
                            mode="determinate", style=strength_style).grid(
                                row=5, column=2, sticky="ew", pady=(0, 2))
            crack_lines = tk.Frame(row, bg="white")
            crack_lines.grid(row=6, column=2, sticky="w", pady=(2, 0))
            tk.Label(crack_lines, text="Estimated crack time (based on entropy; average guesses):",
                     font=("Segoe UI", 9), bg="white", fg="#586174").pack(anchor="w")
            scenarios = (
                ("Offline slow hash (~10K guesses/s)",
                 self.entropy_crack_time(entropy_bits, CRACK_GUESSES_PER_SECOND)),
                ("Offline fast hash (~10B guesses/s)",
                 self.entropy_crack_time(entropy_bits, FAST_HASH_GUESSES_PER_SECOND)),
                ("Online throttled (~100 guesses/hour)",
                 self.entropy_crack_time(entropy_bits, ONLINE_GUESSES_PER_HOUR, 3600)),
            )
            for scenario, estimate in scenarios:
                line = tk.Frame(crack_lines, bg="white")
                line.pack(anchor="w")
                tk.Label(line, text=f"{scenario}: ", font=("Segoe UI", 9),
                         bg="white", fg="#586174").pack(side="left")
                tk.Label(line, text=estimate, font=("Segoe UI", 9, "bold"),
                         bg="white", fg=strength_color).pack(side="left")
            password_entry.configure(
                xscrollcommand=lambda first, last, entry=password_entry, bar=horizontal_scrollbar:
                    self.update_password_scrollbar(entry, bar, first, last)
            )
            password_entry.bind(
                "<Configure>",
                lambda _event, entry=password_entry, bar=horizontal_scrollbar:
                    self.refresh_password_scrollbar(entry, bar)
            )
            password_entry.xview_moveto(0)
            self.root.after_idle(lambda entry=password_entry, bar=horizontal_scrollbar:
                                 self.refresh_password_scrollbar(entry, bar))
            if index == 1:
                tk.Button(
                    self.password_rows, text="Refresh generated values",
                    command=self.refresh_current_output,
                    font=("Segoe UI", 10, "bold"), bg="#e5e9f2", fg="#172033",
                    activebackground="#d5dbea", relief="flat", padx=12, pady=6,
                    cursor="hand2").pack(fill="x", pady=(4, 6))

    def strength_bar_color(self, score):
        if score < 40:
            return "#e53935"  # red: worst or weak
        if score < 60:
            return "#fbc02d"  # yellow: fair
        if score < 80:
            return "#43a047"  # green: good
        return "#aeea00"      # lime: strong
    def entropy_estimate(self, password):
        if self.mode.get() == "token":
            return self.token_bytes.get() * 8
        if self.mode.get() == "pin":
            return int(round(len(password) * math.log2(10)))
        if self.mode.get() == "username":
            pools = self.username_word_pools()
            pattern = self.username_category_options()
            bits = sum(
                math.log2(len(categories))
                + sum(math.log2(len(pools[category])) for category in categories) / len(categories)
                for categories in pattern
            )
            separator = self.username_separator.get()
            gaps = max(0, self.username_word_count.get() - 1)
            if separator == "random_digit":
                bits += gaps * math.log2(10)
            elif separator == "random_mix":
                bits += gaps * (1 + 1.5 * math.log2(10) + math.log2(len(SYMBOLS)))
            return int(round(bits))
        if self.mode.get() == "standard":
            pool_size = (26 if self.lower.get() else 0) + (26 if self.upper.get() else 0)
            pool_size += 10 if self.digits.get() else 0
            pool_size += len(SYMBOLS) if self.symbols.get() else 0
            return int(round(len(password) * math.log2(max(pool_size, 1))))
        if self.use_full_words.get():
            bits = self.word_count.get() * math.log2(len(WORDS))
        else:
            starts = "b c d f g h j k l m n p r s t v w z br cl cr dr fl fr gl gr pl pr sh sk sl sm sn sp st sw tr tw".split()
            endings = "a ab ack ad ag ake al am an at ax e ed ee el en er es et i id ig ile in ip ir is it o ob ock od og op or os ot ox u ub ud ug um un up ur us ut".split()
            bits = self.word_count.get() * math.log2(len(starts) * len(endings))
        if self.add_numbers.get():
            bits += self.word_count.get() * math.log2(10)
        if self.separator.get() == "random_digit":
            bits += max(0, self.word_count.get() - 1) * math.log2(10)
        elif self.separator.get() == "random_mix":
            gap_count = max(0, self.word_count.get() - 1)
            bits += gap_count * (1 + 1.5 * math.log2(10) + math.log2(len(SYMBOLS)))
        return int(round(bits))

    @staticmethod
    def character_set_entropy_estimate(password):
        pool_size = 0
        if any(char.islower() for char in password):
            pool_size += 26
        if any(char.isupper() for char in password):
            pool_size += 26
        if any(char.isdigit() for char in password):
            pool_size += 10
        if any(not char.isalnum() for char in password):
            pool_size += len(SYMBOLS)
        return len(password) * math.log2(max(pool_size, 1))

    def make_api_token(self):
        byte_count = self.token_bytes.get()
        if self.token_encoding.get() == "hex":
            return secrets.token_hex(byte_count)
        return secrets.token_urlsafe(byte_count)

    def make_pin(self):
        return "".join(secrets.choice(string.digits) for _ in range(self.pin_length.get()))

    def refresh_current_output(self):
        if self.mode.get() == "random_number":
            self.generate_random_number()
        elif self.mode.get() == "coin_toss":
            self.toss_coin()
        elif self.mode.get() == "dice_roll":
            self.roll_dice()
        elif self.mode.get() == "casino":
            self.roll_casino()
        elif self.mode.get() == "tarot":
            self.draw_current_tarot()
        else:
            self.generate()

    def toss_coin(self):
        heads = secrets.randbelow(2) == 0
        choice = self.coin_toss_choice.get()
        result = ("Heads" if heads else "Tails") if choice == "Heads / Tails" else ("Yes" if heads else "No")
        self.coin_toss_result.set(result)
        self.coin_toss_history.append((result, choice))
        self.coin_toss_history_list.insert("end", f"{len(self.coin_toss_history)}. {result}")
        self.coin_toss_history_list.see("end")

    def clear_coin_toss_history(self):
        self.coin_toss_history.clear()
        self.coin_toss_history_list.delete(0, "end")

    def roll_dice(self):
        sides = self.dice_sides.get()
        count = self.dice_count.get()
        rolls = [secrets.randbelow(sides) + 1 for _ in range(count)]
        total = sum(rolls)
        self.dice_cumulative_total += total
        self.dice_result.set(
            f"Rolls: {'  |  '.join(str(value) for value in rolls)}\n"
            f"This roll: {total}\nRunning total: {self.dice_cumulative_total}")
        self.dice_history.append((sides, rolls, total))
        roll_text = ", ".join(str(value) for value in rolls)
        self.dice_history_list.insert(
            "end", f"{len(self.dice_history)}. d{sides} × {count}: [{roll_text}] = {total}")
        self.dice_history_list.see("end")

    def clear_dice_history(self):
        self.dice_history.clear()
        self.dice_cumulative_total = 0
        self.dice_result.set("Your roll will appear here.\nRunning total: 0")
        self.dice_history_list.delete(0, "end")

    def roll_casino(self):
        cost = None
        is_consequences = self.casino_play_style.get() == "consequences"
        if is_consequences:
            try:
                cost = int(self.casino_spin_cost.get().strip())
                if cost < 0:
                    raise ValueError("Cost per spin cannot be negative.")
            except ValueError as error:
                messagebox.showerror("Invalid spin cost", str(error))
                return

        symbols = ("💎", "🍒", "⭐", "🔔", "🍋", "7️⃣")
        result = [secrets.choice(symbols) for _ in range(3)]
        base_payouts = {
            "💎": 1000,
            "🍒": 500,
            "⭐": 250,
            "🔔": 100,
        }
        if result[0] == result[1] == result[2]:
            base_payout = base_payouts.get(result[0], 50)
            payout = int(round(base_payout * cost / 10)) if is_consequences else base_payout
            if is_consequences:
                message = f"Jackpot! 3 {result[0]} — ${payout:,} payout"
            else:
                message = f"Jackpot! 3 {result[0]} — {payout:,} points"
        else:
            payout = 0
            message = "No jackpot this time"
        symbols_text = "   ".join(result)
        spin_number = len(self.casino_history) + 1
        if payout:
            unit = "$" if is_consequences else "points"
            self.casino_jackpots.append((payout, spin_number, result[0], unit))
            self.casino_jackpots.sort(key=lambda jackpot: (-jackpot[0], jackpot[1]))
            self.casino_jackpots_list.delete(0, "end")
            for jackpot_payout, jackpot_spin, symbol, jackpot_unit in self.casino_jackpots:
                self.casino_jackpots_list.insert(
                    "end", f"{jackpot_unit}{jackpot_payout:,}  —  Spin #{jackpot_spin}: 3 {symbol}")
        if is_consequences:
            net_change = payout - cost
            self.casino_balance += net_change
            self.casino_balance_label.set(self.format_simulated_money(self.casino_balance))
            self.casino_result.set(
                f"{symbols_text}\n{message}\n"
                f"Cost: ${cost:,}  |  Net this spin: {self.format_simulated_money(net_change)}")
            history_entry = (result, payout, cost, net_change, self.casino_balance)
            history_text = (f"{len(self.casino_history) + 1}. {symbols_text} — "
                            f"cost ${cost:,}, payout ${payout:,}, "
                            f"net {self.format_simulated_money(net_change)}, "
                            f"total {self.format_simulated_money(self.casino_balance)}")
        else:
            self.casino_result.set(f"{symbols_text}\n{message}")
            history_entry = (result, payout, None, None, None)
            history_text = f"{len(self.casino_history) + 1}. {symbols_text} — {message}"
        self.casino_history.append(history_entry)
        self.casino_history_list.insert(
            "end", history_text)
        self.casino_history_list.see("end")

    @staticmethod
    def format_simulated_money(amount):
        if amount < 0:
            return f"-${abs(amount):,}"
        return f"+${amount:,}" if amount > 0 else "$0"

    def update_casino_style(self):
        if self.casino_play_style.get() == "consequences":
            self.casino_cost_frame.pack(fill="x", pady=(6, 2), before=self.casino_net_worth_card)
        else:
            self.casino_cost_frame.pack_forget()
        self.on_casino_cost_changed()

    def select_casino_preset(self, tier_name, cost):
        self.casino_preset_guard = True
        self.casino_spin_cost.set(str(cost))
        self.casino_preset_guard = False
        self.casino_tier_name.set(tier_name)
        for name, button in self.casino_preset_buttons.items():
            button.configure(relief="sunken" if name == tier_name else "flat")
        self.on_casino_cost_changed()

    def on_casino_cost_changed(self):
        try:
            cost = int(self.casino_spin_cost.get().strip())
            valid = cost >= 0
        except (ValueError, tk.TclError):
            valid = False
            cost = 0
        if not self.casino_preset_guard and valid:
            preset_costs = {1: "Bronze", 10: "Silver", 50: "Gold", 100: "Platinum"}
            tier_name = preset_costs.get(cost, "Custom")
            self.casino_tier_name.set(tier_name)
            for name, button in self.casino_preset_buttons.items():
                button.configure(relief="sunken" if name == tier_name else "flat")
        base_payouts = (1000, 500, 250, 100, 50)
        if self.casino_play_style.get() == "consequences":
            payouts = [int(round(base * cost / 10)) for base in base_payouts]
            payout_text = (f"{self.casino_tier_name.get()} payouts at ${cost:,} per spin: "
                           f"3 💎 = ${payouts[0]:,}  |  3 🍒 = ${payouts[1]:,}  |  "
                           f"3 ⭐ = ${payouts[2]:,}  |  3 🔔 = ${payouts[3]:,}  |  "
                           f"other triple = ${payouts[4]:,}")
        else:
            payout_text = ("Free-play jackpots: 3 💎 = 1,000 points  |  3 🍒 = 500 points  |  "
                           "3 ⭐ = 250 points  |  3 🔔 = 100 points  |  other triple = 50 points")
        self.casino_payout_text.set(payout_text)

    def clear_casino_history(self):
        self.casino_history.clear()
        self.casino_jackpots.clear()
        self.casino_jackpots_list.delete(0, "end")
        self.casino_balance = 0
        self.casino_balance_label.set("$0")
        self.casino_history_list.delete(0, "end")

    def update_tarot_spread_mode(self):
        self.three_card_help.pack_forget()
        self.celtic_help.pack_forget()
        if self.tarot_spread_mode.get() == "three":
            self.set_tarot_spread_card_count(3)
            self.tarot_spread_picker.pack(fill="x", pady=(0, 6), before=self.tarot_draw_button)
            self.tarot_draw_button.configure(text="Draw three-card spread")
            self.update_three_card_help()
            self.three_card_help.pack(fill="x", pady=(0, 6), before=self.tarot_draw_button)
            self.tarot_single_result.pack_forget()
            self.tarot_spread_results.pack(fill="x", pady=(2, 0), before=self.tarot_history_header)
        elif self.tarot_spread_mode.get() == "celtic":
            self.set_tarot_spread_card_count(10)
            self.tarot_spread_picker.pack_forget()
            self.tarot_draw_button.configure(text="Draw Celtic Cross")
            self.celtic_help.pack(fill="x", pady=(0, 6), before=self.tarot_draw_button)
            self.tarot_single_result.pack_forget()
            self.tarot_spread_results.pack(fill="x", pady=(2, 0), before=self.tarot_history_header)
        else:
            self.tarot_spread_picker.pack_forget()
            self.tarot_draw_button.configure(text="Draw a tarot card")
            self.tarot_spread_results.pack_forget()
            self.tarot_single_result.pack(fill="x", pady=(2, 0), before=self.tarot_history_header)

    def set_tarot_spread_card_count(self, count):
        for index, widgets in enumerate(self.tarot_spread_cards):
            if index < count:
                if not widgets["frame"].winfo_manager():
                    widgets["frame"].pack(fill="x", pady=(3, 5))
            else:
                widgets["frame"].pack_forget()

    def update_three_card_help(self):
        explanations = {
            "Past — Present — Future": (
                "1 · Past — earlier events or patterns shaping the question.\n"
                "2 · Present — what is active or most relevant now.\n"
                "3 · Future — a possible direction if current influences continue."
            ),
            "Situation — Action — Outcome": (
                "1 · Situation — the central circumstances to understand.\n"
                "2 · Action — a useful response, choice, or approach to consider.\n"
                "3 · Outcome — a possible result of that approach in this situation."
            ),
            "Mind — Body — Spirit": (
                "1 · Mind — thoughts, beliefs, and perspective.\n"
                "2 · Body — physical experience, energy, and practical needs.\n"
                "3 · Spirit — values, meaning, and inner direction.\n"
                "Use this as personal reflection, not health advice or diagnosis."
            ),
            "Problem — Advice — Solution": (
                "1 · Problem — the main difficulty or tension.\n"
                "2 · Advice — a perspective or step that may help.\n"
                "3 · Solution — a possible way through or resolution to work toward."
            ),
        }
        selected = self.tarot_spread_choice.get()
        guidance = explanations.get(selected, "")
        self.three_card_help.configure(
            text=(f"How to read: {selected}\n{guidance}\n\n"
                  "Read from left to right, interpret each card through its position, "
                  "and notice repeated themes. The final card suggests a possibility, "
                  "not a fixed prediction.")
        )

    def draw_current_tarot(self):
        if self.tarot_spread_mode.get() in ("three", "celtic"):
            self.draw_tarot_spread()
            return
        reading = self.create_tarot_card()
        self.tarot_card_name.set(reading["name"])
        self.tarot_orientation.set("Reversed — upside down" if reading["reversed"] else "Upright")
        self.tarot_description.set(reading["description"])
        self.tarot_answer.set(reading["answer"])
        self.tarot_answer_label.configure(
            fg="#a7f06a" if reading["answer"] == "Yes" else "#ff8a80")
        self.current_tarot_image = reading["image"]
        if self.current_tarot_image is None:
            self.tarot_image_label.configure(image="", text="Card image unavailable",
                                             fg="#586174", font=("Segoe UI", 9))
        else:
            self.tarot_image_label.configure(image=self.current_tarot_image, text="")
        self.tarot_history.append((reading,))
        self.tarot_history_list.insert(
            "end", f"{len(self.tarot_history)}. {reading['name']} "
            f"({'reversed' if reading['reversed'] else 'upright'}) — {reading['answer']}")
        self.tarot_history_list.see("end")

    def draw_tarot_spread(self):
        spread_name = ("Celtic Cross — 10 cards"
                       if self.tarot_spread_mode.get() == "celtic"
                       else self.tarot_spread_choice.get())
        positions = self.tarot_spread_positions[spread_name]
        self.set_tarot_spread_card_count(len(positions))
        readings = []
        used_names = set()
        for position in positions:
            reading = self.create_tarot_card(used_names)
            used_names.add(reading["name"])
            readings.append(reading)

        self.tarot_spread_images = []
        image_scale = 3 if len(positions) > 3 else 2
        for position, reading, widgets in zip(positions, readings, self.tarot_spread_cards):
            widgets["frame"].configure(text=position)
            widgets["name"].set(reading["name"])
            widgets["orientation"].set(
                "Reversed — upside down" if reading["reversed"] else "Upright")
            widgets["description"].set(reading["description"])
            widgets["answer"].set(f"Yes / No leaning: {reading['answer']}")
            widgets["answer_label"].configure(
                fg="#238636" if reading["answer"] == "Yes" else "#c62828")
            image = reading["image"]
            if image is None:
                widgets["image"].configure(image="", text="Image unavailable",
                                            fg="#586174", font=("Segoe UI", 8))
                widgets["image_ref"] = None
            else:
                small_image = image.subsample(image_scale, image_scale)
                widgets["image"].configure(image=small_image, text="")
                widgets["image_ref"] = small_image
                self.tarot_spread_images.append(small_image)

        self.tarot_history.append((spread_name, readings))
        names = ", ".join(
            f"{reading['name']} ({'R' if reading['reversed'] else 'U'})"
            for reading in readings)
        self.tarot_history_list.insert(
            "end", f"{len(self.tarot_history)}. {spread_name}: {names}")
        self.tarot_history_list.see("end")

    def create_tarot_card(self, excluded_names=None):
        major_cards = [
            ("The Fool", "Fresh beginnings, openness, and a willingness to explore the unknown.", "Yes"),
            ("The Magician", "Resourcefulness and focused action can turn an idea into something real.", "Yes"),
            ("The High Priestess", "Listen inwardly; important details may not be visible yet.", "No"),
            ("The Empress", "Growth, care, creativity, and conditions that help something flourish.", "Yes"),
            ("The Emperor", "Structure, boundaries, and steady leadership shape the situation.", "Yes"),
            ("The Hierophant", "Established practices, shared values, or trusted guidance are in focus.", "Yes"),
            ("The Lovers", "A meaningful choice calls for honesty, alignment, and connection.", "Yes"),
            ("The Chariot", "Determination and direction can carry you through competing pressures.", "Yes"),
            ("Strength", "Patience and calm courage are more useful than force.", "Yes"),
            ("The Hermit", "Step back, reflect, and seek clarity before moving ahead.", "No"),
            ("Wheel of Fortune", "A turning point or changing circumstances may alter the course.", "Yes"),
            ("Justice", "Fairness, clear facts, and accountability matter to the outcome.", "Yes"),
            ("The Hanged Man", "Pause and consider a different perspective; progress may need to wait.", "No"),
            ("Death", "A chapter is ending so meaningful change can take place; this is not literal death.", "No"),
            ("Temperance", "Balance, patience, and combining resources support gradual progress.", "Yes"),
            ("The Devil", "A limiting attachment or unhealthy pattern may be influencing the choice.", "No"),
            ("The Tower", "A disruption may expose what is unstable and require a reset.", "No"),
            ("The Star", "Renewed hope and a clearer sense of direction are available.", "Yes"),
            ("The Moon", "Uncertainty or incomplete information makes the path hard to read.", "No"),
            ("The Sun", "Clarity, confidence, and joyful momentum surround the situation.", "Yes"),
            ("Judgement", "Review what has happened and answer a call to make a considered choice.", "Yes"),
            ("The World", "A cycle reaches completion, bringing integration and a sense of arrival.", "Yes"),
        ]
        rank_names = ("Ace", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight",
                      "Nine", "Ten", "Page", "Knight", "Queen", "King")
        rank_meanings = {
            "Ace": "a beginning or promising opportunity",
            "Two": "a choice, partnership, or search for balance",
            "Three": "growth through collaboration and expression",
            "Four": "stability, structure, or a need to pause",
            "Five": "friction, challenge, or a shift in circumstances",
            "Six": "support, progress, or restoring harmony",
            "Seven": "assessment, patience, and testing what is worthwhile",
            "Eight": "focused effort, movement, or developing a skill",
            "Nine": "a near culmination and the results of sustained effort",
            "Ten": "completion, responsibility, and the weight of accumulated choices",
            "Page": "curiosity, learning, or an encouraging message",
            "Knight": "pursuit, action, and the way ambition is directed",
            "Queen": "mature understanding, care, and self-possession",
            "King": "leadership, experience, and responsible mastery",
        }
        suit_meanings = {
            "Wands": "creativity, ambition, and personal drive",
            "Cups": "feelings, relationships, and imagination",
            "Swords": "thought, communication, and difficult decisions",
            "Pentacles": "practical matters, work, and material resources",
        }
        yes_ranks = {
            "Wands": {"Ace", "Three", "Four", "Six", "Eight", "Page", "Knight", "Queen", "King"},
            "Cups": {"Ace", "Two", "Three", "Six", "Nine", "Ten", "Knight", "Queen", "King"},
            "Swords": {"Six"},
            "Pentacles": {"Ace", "Three", "Six", "Eight", "Nine", "Ten", "Page", "Knight", "Queen", "King"},
        }
        no_ranks = {
            "Wands": {"Five", "Ten"},
            "Cups": {"Five", "Eight"},
            "Swords": {"Three", "Five", "Seven", "Eight", "Nine", "Ten"},
            "Pentacles": {"Five"},
        }
        deck = list(major_cards)
        for suit, suit_theme in suit_meanings.items():
            for rank in rank_names:
                card_name = f"{rank} of {suit}"
                description = (f"This card points to {rank_meanings[rank]} in the area of "
                               f"{suit_theme}.")
                if rank in yes_ranks[suit]:
                    leaning = "Yes"
                elif rank in no_ranks[suit]:
                    leaning = "No"
                else:
                    leaning = "No" if rank in {"Four", "Seven", "Page"} else "Yes"
                deck.append((card_name, description, leaning))

        excluded_names = excluded_names or set()
        deck = [card for card in deck if card[0] not in excluded_names]
        card_name, description, answer = secrets.choice(deck)
        is_reversed = secrets.randbelow(2) == 1
        if is_reversed:
            description, answer = self.get_reversed_tarot_reading(card_name, answer, description)
        major_image_stems = {
            "The Fool": "00_Fool", "The Magician": "01_Magician",
            "The High Priestess": "02_High_Priestess", "The Empress": "03_Empress",
            "The Emperor": "04_Emperor", "The Hierophant": "05_Hierophant",
            "The Lovers": "06_Lovers", "The Chariot": "07_Chariot",
            "Strength": "08_Strength", "The Hermit": "09_Hermit",
            "Wheel of Fortune": "10_Wheel_of_Fortune", "Justice": "11_Justice",
            "The Hanged Man": "12_Hanged_Man", "Death": "13_Death",
            "Temperance": "14_Temperance", "The Devil": "15_Devil",
            "The Tower": "16_Tower", "The Star": "17_Star",
            "The Moon": "18_Moon", "The Sun": "19_Sun",
            "Judgement": "20_Judgement", "The World": "21_World",
        }
        if card_name in major_image_stems:
            image_stem = major_image_stems[card_name]
        else:
            rank, suit = card_name.split(" of ")
            rank_number = rank_names.index(rank) + 1
            suit_prefix = {"Wands": "Wands", "Cups": "Cups",
                           "Swords": "Swords", "Pentacles": "Pents"}[suit]
            image_stem = f"{suit_prefix}{rank_number:02}"
        image_variant = "_reversed" if is_reversed else ""
        image_path = Path(__file__).resolve().parent / "tarot_cards" / f"{image_stem}{image_variant}.png"
        try:
            image = tk.PhotoImage(file=str(image_path))
        except tk.TclError:
            image = None
        return {
            "name": card_name,
            "description": description,
            "answer": answer,
            "reversed": is_reversed,
            "image": image,
        }

    def get_reversed_tarot_reading(self, card_name, upright_answer, upright_description):
        major_reversals = {
            "The Fool": ("Impulsiveness, poor planning, or fear of taking a sensible first step may be getting in the way.", "No"),
            "The Magician": ("Scattered effort, unused abilities, or misleading intentions may be weakening the plan.", "No"),
            "The High Priestess": ("Intuition may be ignored, or private information may be clouding clear judgement.", "No"),
            "The Empress": ("Creative energy or care may be blocked, neglected, or given without healthy limits.", "No"),
            "The Emperor": ("Rigid control, weak boundaries, or difficulty taking responsibility may be present.", "No"),
            "The Hierophant": ("A rule or tradition may feel restrictive; question it carefully before choosing another path.", "No"),
            "The Lovers": ("Misalignment, imbalance, or avoiding an important choice may be affecting the connection.", "No"),
            "The Chariot": ("Competing directions or a loss of control may be slowing progress.", "No"),
            "Strength": ("Self-doubt, impatience, or frustration may be making a gentle approach harder.", "No"),
            "The Hermit": ("Withdrawal may have become isolation, or useful advice may be kept at a distance.", "No"),
            "Wheel of Fortune": ("Resistance to change or a difficult turn in circumstances may be delaying progress.", "No"),
            "Justice": ("Avoiding accountability or overlooking key facts may lead to an unfair outcome.", "No"),
            "The Hanged Man": ("Stalling or resisting a necessary change of perspective may keep things suspended.", "No"),
            "Death": ("Holding on to an ending chapter may delay the transition that is ready to happen.", "No"),
            "Temperance": ("Imbalance, excess, or impatience may be disrupting a gradual solution.", "No"),
            "The Devil": ("A limiting pattern may be loosening, creating room to reclaim choice and independence.", "Yes"),
            "The Tower": ("Avoiding a needed change may prolong instability; rebuild carefully rather than ignore it.", "No"),
            "The Star": ("Discouragement or disconnection may make hope difficult to access right now.", "No"),
            "The Moon": ("Confusion may be lifting as hidden details or mistaken assumptions come into view.", "Yes"),
            "The Sun": ("Confidence or joy may be temporarily muted, so check expectations and timing.", "No"),
            "Judgement": ("Self-doubt or avoidance may make it difficult to answer an important call for change.", "No"),
            "The World": ("A cycle may feel unfinished; delays or loose ends remain before closure.", "No"),
        }
        if card_name in major_reversals:
            return major_reversals[card_name]

        rank, suit = card_name.split(" of ")
        minor_reversals = {
            "Wands": {
                "Ace": ("A promising spark may be delayed, or motivation may be hard to find.", "No"),
                "Two": ("Fear of the unknown or weak planning may hold back expansion.", "No"),
                "Three": ("Progress may face delays; reassess plans before expecting results.", "No"),
                "Four": ("A celebration or stable phase may be disrupted, or home life may feel unsettled.", "No"),
                "Five": ("Avoided tension or unresolved competition may still need to be addressed.", "No"),
                "Six": ("Recognition may be delayed, or confidence may depend too heavily on approval.", "No"),
                "Seven": ("Pressure may feel overwhelming; reconsider which challenges are worth defending.", "No"),
                "Eight": ("Plans may stall through delays, frustration, or resistance to change.", "No"),
                "Nine": ("Exhaustion can make it difficult to keep defending the same position.", "No"),
                "Ten": ("Overload points to the need to set limits or share responsibilities.", "Yes"),
                "Page": ("Scattered enthusiasm or procrastination may keep an idea from taking shape.", "No"),
                "Knight": ("Impulsive action, anger, or unreliable follow-through may create setbacks.", "No"),
                "Queen": ("Insecurity, jealousy, or demanding behavior may be affecting confidence and warmth.", "No"),
                "King": ("Impatience or domineering ambition may undermine otherwise strong leadership.", "No"),
            },
            "Cups": {
                "Ace": ("Emotional openness may be blocked, or a new connection may not feel fulfilling yet.", "No"),
                "Two": ("Miscommunication or imbalance may strain a partnership.", "No"),
                "Three": ("Overindulgence, gossip, or social tension may be taking the joy out of a gathering.", "No"),
                "Four": ("Withdrawal may be easing; notice an offer or possibility you previously dismissed.", "Yes"),
                "Five": ("Acceptance and forgiveness can help you move beyond disappointment.", "Yes"),
                "Six": ("Nostalgia may keep you stuck in the past, or it may be time to grow beyond it.", "No"),
                "Seven": ("Unrealistic options are falling away, making a clearer choice possible.", "Yes"),
                "Eight": ("Fear of change or uncertainty may make it hard to leave an unfulfilling situation.", "No"),
                "Nine": ("Dissatisfaction or excess may remain beneath an appearance of comfort.", "No"),
                "Ten": ("Family strain or unmet expectations may disrupt a sense of belonging.", "No"),
                "Page": ("Emotional immaturity or wishful thinking may obscure what is actually being offered.", "No"),
                "Knight": ("Moodiness, jealousy, or unrealistic romantic expectations may complicate matters.", "No"),
                "Queen": ("Insecurity or blurred boundaries may make it harder to care for yourself and others.", "No"),
                "King": ("Emotional volatility or manipulation may be replacing balanced, compassionate judgement.", "No"),
            },
            "Swords": {
                "Ace": ("Confusion or poor communication may cloud a decision that needs clear facts.", "No"),
                "Two": ("Avoidance or information overload may prolong indecision.", "No"),
                "Three": ("Healing and forgiveness may be beginning after a painful disappointment.", "Yes"),
                "Four": ("Restlessness or burnout may make proper recovery difficult.", "No"),
                "Five": ("A conflict may be easing, but resentment or the cost of winning still needs attention.", "Yes"),
                "Six": ("Resistance to transition may keep unresolved problems close by.", "No"),
                "Seven": ("A concealed truth may come to light, creating a chance to correct course.", "Yes"),
                "Eight": ("A sense of restriction can loosen when you question limiting assumptions.", "Yes"),
                "Nine": ("Worry may be easing as fears are faced and support is accepted.", "Yes"),
                "Ten": ("Recovery is possible after a difficult ending, though it may take time.", "Yes"),
                "Page": ("Gossip, evasiveness, or hasty conclusions may distort the facts.", "No"),
                "Knight": ("Scattered action or aggression without a plan can create needless conflict.", "No"),
                "Queen": ("Bitterness or harsh judgement may be making honest communication difficult.", "No"),
                "King": ("Manipulation or misuse of authority may replace clear and fair reasoning.", "No"),
            },
            "Pentacles": {
                "Ace": ("Poor planning or a missed practical detail may delay a new opportunity.", "No"),
                "Two": ("Overcommitment or disorganization may make competing demands hard to manage.", "No"),
                "Three": ("Weak teamwork or uneven standards may reduce the quality of shared work.", "No"),
                "Four": ("Possessiveness or fear of loss may be restricting healthy use of resources.", "No"),
                "Five": ("Hardship may begin to ease as help, recovery, or new options become visible.", "Yes"),
                "Six": ("Generosity may be uneven, conditional, or tied to an uncomfortable obligation.", "No"),
                "Seven": ("Impatience or poor assessment may lead to abandoning work before it matures.", "No"),
                "Eight": ("Careless work or perfectionism may interfere with steady skill-building.", "No"),
                "Nine": ("Overspending or dependence on approval may undermine independence.", "No"),
                "Ten": ("Family or financial instability may challenge long-term security.", "No"),
                "Page": ("Procrastination or lack of follow-through may stall a useful learning opportunity.", "No"),
                "Knight": ("Stagnation or excessive caution may prevent practical progress.", "No"),
                "Queen": ("Neglecting self-care or becoming overprotective may disturb a stable routine.", "No"),
                "King": ("Reckless spending or stubborn control may put material security at risk.", "No"),
            },
        }
        return minor_reversals[suit][rank]

    def clear_tarot_history(self):
        self.tarot_history.clear()
        self.tarot_history_list.delete(0, "end")

    def generate_random_number(self):
        try:
            minimum = int(self.random_minimum.get().strip())
            maximum = int(self.random_maximum.get().strip())
            if minimum > maximum:
                raise ValueError("Minimum must be less than or equal to maximum.")
            number = secrets.randbelow(maximum - minimum + 1) + minimum
            self.random_number_result.set(str(number))
            self.random_number_history.append((number, minimum, maximum))
            self.random_number_history_list.insert(
                "end", f"{len(self.random_number_history)}. {number}  (range {minimum}–{maximum})")
            self.random_number_history_list.see("end")
        except ValueError as error:
            messagebox.showerror("Invalid number range", str(error))

    def clear_random_number_history(self):
        self.random_number_history.clear()
        self.random_number_history_list.delete(0, "end")

    def username_word_pools(self):
        pools = {}
        if self.username_adjectives.get():
            pools["adjective"] = USERNAME_ADJECTIVES
        if self.username_nouns.get():
            pools["noun"] = USERNAME_NOUNS
        if self.username_verbs.get():
            pools["verb"] = USERNAME_VERBS
        if not pools:
            raise ValueError("Select at least one word type for the username.")
        return pools

    def username_category_options(self):
        active = tuple(self.username_word_pools())
        count = self.username_word_count.get()
        if count == 1:
            return [active]

        if "noun" not in active:
            return [active for _ in range(count)]

        preceding = tuple(category for category in active if category != "noun")
        if not preceding:
            return [("noun",) for _ in range(count)]

        pattern = []
        if "adjective" in preceding and "verb" in preceding and count >= 3:
            pattern.extend([("adjective",), ("verb",)])
            pattern.extend([preceding] * max(0, count - 3))
        else:
            pattern.extend([preceding] * (count - 1))
        pattern.append(("noun",))
        return pattern

    def make_username(self):
        pools = self.username_word_pools()
        parts = [
            secrets.choice(pools[category])
            for categories in self.username_category_options()
            for category in (secrets.choice(categories),)
        ]
        if self.username_capitalize.get():
            parts = [part.capitalize() for part in parts]
        if self.username_leetspeak.get():
            parts = [part.translate(LEET_TABLE) for part in parts]

        separator = self.username_separator.get()
        if separator == "random_digit":
            return "".join(
                (secrets.choice(string.digits) if index else "") + part
                for index, part in enumerate(parts)
            )
        if separator == "random_mix":
            return parts[0] + "".join(
                "".join(secrets.choice(string.digits) for _ in range(secrets.randbelow(2) + 1))
                + secrets.choice(SYMBOLS) + part
                for part in parts[1:]
            )
        return separator.join(parts)

    def password_strength(self, password):
        if zxcvbn is None:
            return None, None, None, None

        result = zxcvbn(password, max_length=max(72, len(password)))
        rating = ("Worst", "Weak", "Fair", "Good", "Strong")[result["score"]]
        crack_time = result["crack_times_display"]["offline_fast_hashing_1e10_per_second"]
        guesses_log10 = float(result.get("guesses_log10", math.log10(max(1, result["guesses"]))))
        entropy_bits = guesses_log10 * math.log2(10)
        return rating, result["score"], crack_time, entropy_bits

    def entropy_strength_rating(self, entropy_bits):
        if entropy_bits < 20:
            return "Worst"
        if entropy_bits < 40:
            return "Weak"
        if entropy_bits < 60:
            return "Fair"
        if entropy_bits < 80:
            return "Good"
        return "Strong"

    def entropy_crack_time(self, entropy_bits, guesses_per_rate, seconds_per_rate=1):
        average_guesses = 1 << max(0, entropy_bits - 1)
        seconds = average_guesses * seconds_per_rate // guesses_per_rate
        if seconds < 1:
            return "under 1 second"
        if seconds < 60:
            return f"about {seconds} seconds"
        if seconds < 3600:
            return f"about {seconds // 60} minutes"
        if seconds < 86400:
            return f"about {seconds // 3600} hours"
        if seconds < 365 * 86400:
            return f"about {seconds // 86400} days"
        years = seconds // (365 * 86400)
        if years < 1000:
            return f"about {years:,} years"
        digits = str(years)
        if len(digits) < 7:
            return f"about {years // 1000:,} thousand years"
        return f"about {digits[0]}.{digits[1:3]}e+{len(digits) - 1} years"
    def update_password_scrollbar(self, entry, scrollbar, first, last):
        scrollbar.set(first, last)
        if float(first) > 0 or float(last) < 1:
            scrollbar.grid()
        else:
            scrollbar.grid_remove()

    def refresh_password_scrollbar(self, entry, scrollbar):
        first, last = entry.xview()
        self.update_password_scrollbar(entry, scrollbar, first, last)
    def make_memorable_password(self):
        if self.use_full_words.get():
            parts = [secrets.choice(WORDS) for _ in range(self.word_count.get())]
        else:
            starts = "b c d f g h j k l m n p r s t v w z br cl cr dr fl fr gl gr pl pr sh sk sl sm sn sp st sw tr tw".split()
            endings = "a ab ack ad ag ake al am an at ax e ed ee el en er es et i id ig ile in ip ir is it o ob ock od og op or os ot ox u ub ud ug um un up ur us ut".split()
            parts = [secrets.choice(starts) + secrets.choice(endings) for _ in range(self.word_count.get())]
        if self.capitalize_first.get():
            parts[0] = parts[0][0].upper() + parts[0][1:]

        if self.leetspeak.get():
            preserved_first = parts[0][0] if self.capitalize_first.get() else None
            leet_table = str.maketrans({
                "a": "4", "A": "4", "e": "3", "E": "3",
                "i": "1", "I": "1", "o": "0", "O": "0",
                "s": "5", "S": "5", "t": "7", "T": "7",
            })
            parts = [part.translate(leet_table) for part in parts]
            if preserved_first is not None:
                parts[0] = preserved_first + parts[0][1:]

        if self.add_numbers.get():
            parts = [part + secrets.choice(string.digits) for part in parts]

        if self.separator.get() == "random_digit":
            separators = [secrets.choice(string.digits) for _ in range(len(parts) - 1)]
            return "".join(part + (separators[index] if index < len(separators) else "")
                           for index, part in enumerate(parts))
        if self.separator.get() == "random_mix":
            separators = [
                "".join(secrets.choice(string.digits) for _ in range(secrets.randbelow(2) + 1))
                + secrets.choice(SYMBOLS)
                for _ in range(len(parts) - 1)
            ]
            return "".join(part + (separators[index] if index < len(separators) else "")
                           for index, part in enumerate(parts))

        return self.separator.get().join(parts)

    def confirm_password_copy(self, passwords):
        if self.mode.get() not in ("standard", "memorable"):
            return True

        weak_passwords = [
            (password, self.generated_password_entropy[password])
            for password in passwords
            if password in self.generated_password_entropy
            and self.entropy_strength_rating(
                self.generated_password_entropy[password]
            ) != "Strong"
        ]
        if not weak_passwords:
            return True

        if len(weak_passwords) == 1:
            _password, bits = weak_passwords[0]
            rating = self.entropy_strength_rating(bits)
            message = (
                f"This {self.mode.get()} password is rated {rating} "
                f"(~{bits} bits of entropy), below Strong.\n\n"
                "Copy it anyway?"
            )
        else:
            message = (
                f"{len(weak_passwords)} of the {len(passwords)} generated "
                "passwords are rated below Strong by the entropy estimate.\n\n"
                "Copy them anyway?"
            )
        return messagebox.askyesno("Password strength warning", message, parent=self.root)

    def copy_password(self, password):
        if not self.confirm_password_copy([password]):
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        self.root.update()

    def copy_all(self):
        passwords = [
            row.winfo_children()[2].get()
            for row in self.password_rows.winfo_children()
        ]
        if passwords and self.confirm_password_copy(passwords):
            self.root.clipboard_clear()
            self.root.clipboard_append("\n".join(passwords))
            self.root.update()

if __name__ == "__main__":
    window = tk.Tk()
    PasswordGeneratorApp(window)
    window.mainloop()
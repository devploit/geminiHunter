"""Compiled regex patterns for Google API key extraction."""

import re

# Standard Google API key: AIzaSy followed by 33 alphanumeric/dash/underscore chars
GOOGLE_API_KEY_RE = re.compile(r"AIzaSy[a-zA-Z0-9_-]{33}")

# Split/concatenated key patterns in JS
# e.g., "AIzaSy" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567"
SPLIT_KEY_CONCAT = re.compile(
    r"""["']AIzaSy["']\s*\+\s*["']([a-zA-Z0-9_-]+)["']""",
    re.MULTILINE,
)

# Template literal: `AIzaSy${var}`
SPLIT_KEY_TEMPLATE = re.compile(
    r"""`AIzaSy\$\{([^}]+)\}`""",
    re.MULTILINE,
)

# Array join pattern: ["AIzaSy","rest"].join("")
SPLIT_KEY_ARRAY_JOIN = re.compile(
    r"""\["AIzaSy"\s*,\s*"([a-zA-Z0-9_-]+)"\]\s*\.\s*join\s*\(\s*["']["']\s*\)""",
    re.MULTILINE,
)

# Reverse pattern: key stored reversed
# "76543210ZYXWVUTSRQPONMLKJIHGFEDCBA" reversed starts with AIzaSy
REVERSE_KEY_RE = re.compile(
    r"""["']([a-zA-Z0-9_-]{33}ySazIA)["']""",
)

# --- New patterns ---

# Multi-part concatenation: "AIzaSy" + "part1" + "part2" + ...
# Matches the whole expression; use CONCAT_PART_RE to extract individual parts
MULTILINE_CONCAT_RE = re.compile(
    r"""["']AIzaSy["']\s*(?:\+\s*["'][a-zA-Z0-9_-]+["']\s*){2,}""",
    re.DOTALL,
)

# Helper to extract individual string parts from a multiline concat match
CONCAT_PART_RE = re.compile(r"""["']([a-zA-Z0-9_-]+)["']""")

# Fallback/default value: || "AIzaSy..."
FALLBACK_KEY_RE = re.compile(
    r"""\|\|\s*["'](AIzaSy[a-zA-Z0-9_-]{33})["']"""
)

# Hex-encoded prefix: "\x41\x49\x7a\x61\x53\x79" = "AIzaSy"
HEX_PREFIX_RE = re.compile(
    r"""(?:\\x41\\x49\\x7[aA]\\x61\\x53\\x79)([a-zA-Z0-9_-]{33})"""
)

# Base64-encoded full key: btoa("AIzaSy...") = "QUl6YVN5..."
# "AIzaSy" base64-encodes to "QUl6YVN5"; full 39-byte key = 52 base64 chars (no padding)
BASE64_KEY_RE = re.compile(
    r"""["'](QUl6YVN5[A-Za-z0-9+/\-_]{44}=?=?)["']"""
)

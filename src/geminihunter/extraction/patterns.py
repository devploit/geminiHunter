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
    r"""["']([a-zA-Z0-9_-]{33}ySzIA)["']""",
)

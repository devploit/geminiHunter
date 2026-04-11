"""JS deobfuscation / beautification before key extraction."""

import logging
import re

import jsbeautifier

logger = logging.getLogger("geminihunter")

# Detect split key fragments: "AIzaSy" as a standalone string (not followed by 33 chars)
_SPLIT_HINT_RE = re.compile(r"""["']AIzaSy["']""")
_FULL_KEY_RE = re.compile(r"AIzaSy[a-zA-Z0-9_-]{33}")


class Deobfuscator:
    """Beautifies minified JS only when split/obfuscated keys are suspected."""

    def __init__(self):
        self.opts = jsbeautifier.default_options()
        self.opts.indent_size = 2
        self.opts.preserve_newlines = True
        self.opts.max_preserve_newlines = 2
        self.opts.wrap_line_length = 0  # Don't wrap

    def process(self, content: str) -> str:
        """
        Only beautify if the content has split key fragments ("AIzaSy" + ...)
        but no full keys. Full keys are found by regex on raw content just fine.
        """
        if not content:
            return content

        # If there are split key hints but no full keys, beautify to help extraction
        if _SPLIT_HINT_RE.search(content) and not _FULL_KEY_RE.search(content):
            try:
                return jsbeautifier.beautify(content, self.opts)
            except Exception as e:
                logger.debug(f"Beautification failed: {e}")

        return content

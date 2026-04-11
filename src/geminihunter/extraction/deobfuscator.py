"""JS deobfuscation / beautification before key extraction."""

import logging

import jsbeautifier

logger = logging.getLogger("geminihunter")


class Deobfuscator:
    """Beautifies minified JS to improve regex extraction accuracy."""

    def __init__(self):
        self.opts = jsbeautifier.default_options()
        self.opts.indent_size = 2
        self.opts.preserve_newlines = True
        self.opts.max_preserve_newlines = 2
        self.opts.wrap_line_length = 0  # Don't wrap

    def process(self, content: str) -> str:
        """
        Beautify JS content. Returns original content on failure.

        Only processes content that looks like minified JS (heuristic:
        average line length > 500 chars).
        """
        if not content:
            return content

        # Heuristic: only beautify if it looks minified
        lines = content.split("\n")
        if lines:
            avg_line_len = len(content) / len(lines)
            if avg_line_len < 500:
                return content  # Probably not minified, skip

        try:
            return jsbeautifier.beautify(content, self.opts)
        except Exception as e:
            logger.debug(f"Beautification failed: {e}")
            return content

"""Global configuration dataclass."""

import math
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Config:
    # Targets (discovery mode)
    targets: list[str] = field(default_factory=list)

    # Direct keys (key-check mode)
    keys: list[str] = field(default_factory=list)

    # APK scanning
    apk_paths: list[str] = field(default_factory=list)

    # Discovery options
    depth: int = 2
    wayback: bool = True
    sourcemaps: bool = True

    # Validation options
    bypass: bool = True

    # OPSEC
    proxy: str | None = None
    rate_limit: float = 10.0
    delay: float = 0.0
    timeout: float = 15.0
    concurrency: int = 20
    user_agent: str = "rotate"
    insecure: bool = False

    # Output
    json_mode: bool = False
    verbose: bool = False
    quiet: bool = False
    evidence: bool = False
    output_path: str | None = None

    def __post_init__(self) -> None:
        for name, minimum in (("depth", 0), ("concurrency", 1)):
            value = getattr(self, name)
            if type(value) is not int or value < minimum:
                raise ValueError(f"{name} must be an integer >= {minimum}")
        for name in ("rate_limit", "timeout", "delay"):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value < 0
                or (name != "delay" and value == 0)
            ):
                bound = ">= 0" if name == "delay" else "> 0"
                raise ValueError(f"{name.replace('_', '-')} must be finite and {bound}")

    @property
    def writes_json(self) -> bool:
        return self.json_mode or bool(
            self.output_path and self.output_path.lower().endswith(".json")
        )

    @property
    def is_key_mode(self) -> bool:
        return len(self.keys) > 0

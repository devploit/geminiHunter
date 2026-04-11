"""Global configuration dataclass."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Config:
    # Targets (discovery mode)
    targets: list[str] = field(default_factory=list)

    # Direct keys (key-check mode)
    keys: list[str] = field(default_factory=list)

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

    # Output
    json_mode: bool = False
    verbose: bool = False
    quiet: bool = False
    evidence: bool = False
    output_path: str | None = None

    @property
    def is_key_mode(self) -> bool:
        return len(self.keys) > 0

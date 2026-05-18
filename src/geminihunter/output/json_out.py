"""JSON output formatter."""


from geminihunter.models import ScanResult


def render_json(result: ScanResult) -> str:
    """Render scan results as JSON string."""
    return result.model_dump_json(indent=2)

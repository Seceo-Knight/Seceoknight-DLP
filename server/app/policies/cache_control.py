"""
Policy cache control — shared counter for cache invalidation.

Separated into its own module to avoid circular imports between
database_policy_evaluator and policy_service.
"""

_policy_cache_generation: int = 0


def bump_policy_cache() -> None:
    """Increment the generation counter so evaluators refresh on next call."""
    global _policy_cache_generation
    _policy_cache_generation += 1


def get_policy_cache_generation() -> int:
    """Read the current generation (used by evaluator to detect staleness)."""
    return _policy_cache_generation

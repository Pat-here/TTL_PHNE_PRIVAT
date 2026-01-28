import os

from dotenv import load_dotenv


def _env(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name, default)
    if value is None:
        return None
    value = value.strip()
    return value if value else None


def load_config() -> dict:
    """
    Centralne miejsce konfiguracji dla serwera licencyjnego.
    """
    load_dotenv(override=True)

    cfg = {
        "FLASK_SECRET_KEY": _env("SECRET_KEY"),
        "ADMIN_PASSWORD": _env("ADMIN_PASSWORD"),
        "ADMIN_ID": _env("ADMIN_ID"),
        "SUPABASE_URL": _env("SUPABASE_URL"),
        "SUPABASE_KEY": _env("SUPABASE_KEY"),
        # Ustawienia API:
        "API_RATE_LIMIT_PER_MINUTE": int(_env("API_RATE_LIMIT_PER_MINUTE", "120") or "120"),
        "API_RATE_LIMIT_BURST": int(_env("API_RATE_LIMIT_BURST", "30") or "30"),
    }
    return cfg


def require_config(cfg: dict, keys: list[str]) -> None:
    missing = [k for k in keys if not cfg.get(k)]
    if missing:
        raise RuntimeError(f"Brakuje wymaganych zmiennych środowiskowych: {', '.join(missing)}")

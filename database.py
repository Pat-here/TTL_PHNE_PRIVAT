from __future__ import annotations

from supabase import Client, create_client

from config import load_config, require_config

_db: Client | None = None


def get_db() -> Client:
    """
    Singleton klienta Supabase.
    """
    global _db
    if _db is not None:
        return _db

    cfg = load_config()
    require_config(cfg, ["SUPABASE_URL", "SUPABASE_KEY"])
    _db = create_client(cfg["SUPABASE_URL"], cfg["SUPABASE_KEY"])
    return _db
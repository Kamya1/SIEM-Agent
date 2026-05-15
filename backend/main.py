"""Run: uvicorn main:app --reload --port 8000 (from backend/)."""

from app.main import app

__all__ = ["app"]

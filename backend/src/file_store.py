import hashlib
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List


class TextBackedStore:
    """Simple file-backed JSON store for auth users, sessions, and discussion posts."""

    def __init__(self, store_file: Path):
        self.store_file = store_file
        self.store_file.parent.mkdir(parents=True, exist_ok=True)
        self.data = self._load()

    def _load(self) -> dict:
        if not self.store_file.exists():
            return {"users": {}, "sessions": {}, "posts": []}

        with self.store_file.open("r", encoding="utf-8") as file:
            raw = file.read().strip()
            if not raw:
                return {"users": {}, "sessions": {}, "posts": []}
            return json.loads(raw)

    def _save(self) -> None:
        with self.store_file.open("w", encoding="utf-8") as file:
            file.write(json.dumps(self.data, indent=2))

    def create_user(self, username: str, password: str) -> None:
        if username in self.data["users"]:
            raise ValueError("Username already exists.")

        salt = secrets.token_hex(16)
        password_hash = hashlib.sha256(f"{salt}:{password}".encode("utf-8")).hexdigest()
        self.data["users"][username] = {
            "password_salt": salt,
            "password_hash": password_hash,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self._save()

    def authenticate_user(self, username: str, password: str) -> str:
        user = self.data["users"].get(username)
        if user is None:
            raise ValueError("Invalid username or password.")

        candidate_hash = hashlib.sha256(
            f"{user['password_salt']}:{password}".encode("utf-8")
        ).hexdigest()
        if candidate_hash != user["password_hash"]:
            raise ValueError("Invalid username or password.")

        token = secrets.token_urlsafe(32)
        self.data["sessions"][token] = {
            "username": username,
            "issued_at": datetime.now(timezone.utc).isoformat(),
        }
        self._save()
        return token

    def get_user_by_token(self, token: str) -> str:
        session = self.data["sessions"].get(token)
        if session is None:
            raise ValueError("Invalid or expired token.")
        return session["username"]

    def create_post(self, username: str, content: str) -> dict:
        post = {
            "id": len(self.data["posts"]) + 1,
            "author": username,
            "content": content,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self.data["posts"].append(post)
        self._save()
        return post

    def list_posts(self) -> List[Dict[str, str]]:
        return sorted(self.data["posts"], key=lambda p: p["id"], reverse=True)

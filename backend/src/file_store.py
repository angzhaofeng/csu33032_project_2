import hashlib
import secrets
from datetime import datetime, timezone
from typing import Dict, List
import firebase_admin
from firebase_admin import credentials, firestore


class TextBackedStore:
    """Firestore-backed store for auth users, sessions, and discussion posts."""

    def __init__(self, store_file: str = None):
        """
        Initialize Firestore connection.
        Args:
            store_file: Path to Firebase credentials JSON (e.g., 'firebase.json').
                       If not provided, uses Application Default Credentials.
        """
        try:
            # Try to initialize if not already initialized
            firebase_admin.get_app()
        except ValueError:
            # App not initialized yet
            if store_file:
                cred = credentials.Certificate(store_file)
                firebase_admin.initialize_app(cred)
            else:
                firebase_admin.initialize_app()

        self.db = firestore.client()

    def create_user(self, username: str, password: str) -> None:
        user_ref = self.db.collection('users').document(username)
        if user_ref.get().exists:
            raise ValueError("Username already exists.")

        salt = secrets.token_hex(16)
        password_hash = hashlib.sha256(f"{salt}:{password}".encode("utf-8")).hexdigest()
        user_ref.set({
            "password_salt": salt,
            "password_hash": password_hash,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })

    def authenticate_user(self, username: str, password: str) -> str:
        user_doc = self.db.collection('users').document(username).get()
        if not user_doc.exists:
            raise ValueError("Invalid username or password.")

        user_data = user_doc.to_dict()
        candidate_hash = hashlib.sha256(
            f"{user_data['password_salt']}:{password}".encode("utf-8")
        ).hexdigest()
        if candidate_hash != user_data["password_hash"]:
            raise ValueError("Invalid username or password.")

        token = secrets.token_urlsafe(32)
        self.db.collection('sessions').document(token).set({
            "username": username,
            "issued_at": datetime.now(timezone.utc).isoformat(),
        })
        return token

    def get_user_by_token(self, token: str) -> str:
        session_doc = self.db.collection('sessions').document(token).get()
        if not session_doc.exists:
            raise ValueError("Invalid or expired token.")
        return session_doc.to_dict()["username"]

    def create_post(self, username: str, content: str) -> dict:
        posts_ref = self.db.collection('posts')
        # Get all posts to determine next ID
        existing_posts = posts_ref.stream()
        max_id = max([doc.to_dict().get('id', 0) for doc in existing_posts], default=0)
        post_id = max_id + 1
        
        post = {
            "id": post_id,
            "author": username,
            "content": content,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        posts_ref.document(str(post_id)).set(post)
        return post

    def list_posts(self) -> List[Dict[str, str]]:
        posts_ref = self.db.collection('posts')
        posts = [doc.to_dict() for doc in posts_ref.stream()]
        return sorted(posts, key=lambda p: p["id"], reverse=True)

import base64
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Dict, List

import firebase_admin
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID
from firebase_admin import credentials, firestore


class TextBackedStore:
    """Firestore-backed secure store with cert-based group key management."""

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
        self._ensure_ca_exists()

    def _utcnow(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _b64encode(self, data: bytes) -> str:
        return base64.b64encode(data).decode("ascii")

    def _b64decode(self, data: str) -> bytes:
        return base64.b64decode(data.encode("ascii"))

    def _load_private_key(self, pem: str):
        return serialization.load_pem_private_key(pem.encode("utf-8"), password=None)

    def _load_public_key(self, pem: str):
        return serialization.load_pem_public_key(pem.encode("utf-8"))

    def _ensure_ca_exists(self) -> None:
        ca_ref = self.db.collection("system").document("ca")
        if ca_ref.get().exists:
            return

        ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_public_key = ca_private_key.public_key()

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "IE"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure Social"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Secure Social Local CA"),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_private_key, hashes.SHA256())
        )

        ca_ref.set(
            {
                "private_key_pem": ca_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ).decode("utf-8"),
                "certificate_pem": cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
                "created_at": self._utcnow(),
            }
        )

    def _issue_user_certificate(self, username: str, user_public_key) -> str:
        ca_doc = self.db.collection("system").document("ca").get()
        if not ca_doc.exists:
            raise ValueError("Certificate authority not initialized.")

        ca_data = ca_doc.to_dict()
        ca_private_key = self._load_private_key(ca_data["private_key_pem"])
        ca_cert = x509.load_pem_x509_certificate(ca_data["certificate_pem"].encode("utf-8"))

        user_subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "IE"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure Social"),
                x509.NameAttribute(NameOID.COMMON_NAME, username),
            ]
        )

        user_cert = (
            x509.CertificateBuilder()
            .subject_name(user_subject)
            .issuer_name(ca_cert.subject)
            .public_key(user_public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(ca_private_key, hashes.SHA256())
        )

        return user_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    def _group_ref(self, group_name: str):
        return self.db.collection("groups").document(group_name)

    def _group_key_ref(self, group_name: str, version: int):
        return self._group_ref(group_name).collection("keys").document(str(version))

    def _members(self, group_name: str) -> List[str]:
        group_doc = self._group_ref(group_name).get()
        if not group_doc.exists:
            return []
        return group_doc.to_dict().get("members", [])

    def _create_group_key(self, group_name: str, members: List[str]) -> None:
        """Create the initial group key and wrap it for all members."""
        raw_group_key = AESGCM.generate_key(bit_length=256)

        wrapped_keys: Dict[str, str] = {}
        for member in members:
            member_doc = self.db.collection("users").document(member).get()
            if not member_doc.exists:
                continue
            member_data = member_doc.to_dict()
            public_key = self._load_public_key(member_data["public_key_pem"])
            wrapped = public_key.encrypt(
                raw_group_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            wrapped_keys[member] = self._b64encode(wrapped)

        # Store key version 1 (only version for this group, never rotated)
        self._group_key_ref(group_name, 1).set(
            {
                "version": 1,
                "wrapped_keys": wrapped_keys,
                "created_at": self._utcnow(),
            }
        )

    def _add_wrapped_key_for_member(self, group_name: str, username: str) -> None:
        """Add a wrapped key entry for a new member using the existing group key."""
        key_doc = self._group_key_ref(group_name, 1).get()
        if not key_doc.exists:
            raise ValueError("Group key not initialized.")

        # Get the existing raw key by unwrapping it from any current member
        members = self._members(group_name)
        if not members:
            raise ValueError("No members in group to derive key from.")

        # Find any current member to unwrap the key
        raw_group_key = None
        for member in members:
            try:
                raw_group_key = self._unwrap_group_key_for_user(group_name, member, 1)
                break
            except ValueError:
                continue

        if raw_group_key is None:
            raise ValueError("Could not unwrap group key.")

        # Wrap the same key for the new member
        user_doc = self.db.collection("users").document(username).get()
        if not user_doc.exists:
            raise ValueError("User does not exist.")

        user_data = user_doc.to_dict()
        public_key = self._load_public_key(user_data["public_key_pem"])
        wrapped = public_key.encrypt(
            raw_group_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Update the wrapped_keys map
        wrapped_keys = key_doc.to_dict().get("wrapped_keys", {})
        wrapped_keys[username] = self._b64encode(wrapped)

        self._group_key_ref(group_name, 1).set(
            {
                "version": 1,
                "wrapped_keys": wrapped_keys,
                "created_at": key_doc.to_dict().get("created_at", self._utcnow()),
            }
        )

    def _remove_wrapped_key_for_member(self, group_name: str, username: str) -> None:
        """Remove a member's wrapped key entry from the group key."""
        key_doc = self._group_key_ref(group_name, 1).get()
        if not key_doc.exists:
            raise ValueError("Group key not initialized.")

        wrapped_keys = key_doc.to_dict().get("wrapped_keys", {})
        if username not in wrapped_keys:
            raise ValueError("User does not have a wrapped key in this group.")

        del wrapped_keys[username]

        self._group_key_ref(group_name, 1).set(
            {
                "version": 1,
                "wrapped_keys": wrapped_keys,
                "created_at": key_doc.to_dict().get("created_at", self._utcnow()),
            }
        )

    def _unwrap_group_key_for_user(self, group_name: str, username: str, version: int) -> bytes:
        key_doc = self._group_key_ref(group_name, version).get()
        if not key_doc.exists:
            raise ValueError("Group key version not found.")

        wrapped_keys = key_doc.to_dict().get("wrapped_keys", {})
        wrapped_key_b64 = wrapped_keys.get(username)
        if not wrapped_key_b64:
            raise ValueError("User is not an active member of the secure group.")

        user_doc = self.db.collection("users").document(username).get()
        if not user_doc.exists:
            raise ValueError("User does not exist.")
        user_private_key = self._load_private_key(user_doc.to_dict()["private_key_pem"])

        return user_private_key.decrypt(
            self._b64decode(wrapped_key_b64),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def _encrypt_content(self, plaintext: str, key: bytes) -> Dict[str, str]:
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return {
            "nonce_b64": self._b64encode(nonce),
            "ciphertext_b64": self._b64encode(ciphertext),
        }

    def _decrypt_content(self, nonce_b64: str, ciphertext_b64: str, key: bytes) -> str:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(self._b64decode(nonce_b64), self._b64decode(ciphertext_b64), None)
        return plaintext.decode("utf-8")

    def create_user(self, username: str, password: str) -> None:
        user_ref = self.db.collection('users').document(username)
        if user_ref.get().exists:
            raise ValueError("Username already exists.")

        salt = secrets.token_hex(16)
        password_hash = hashlib.sha256(f"{salt}:{password}".encode("utf-8")).hexdigest()

        user_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        user_public_key = user_private_key.public_key()

        user_private_key_pem = user_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        user_public_key_pem = user_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        user_cert_pem = self._issue_user_certificate(username, user_public_key)

        user_ref.set({
            "password_salt": salt,
            "password_hash": password_hash,
            "public_key_pem": user_public_key_pem,
            "private_key_pem": user_private_key_pem,
            "certificate_pem": user_cert_pem,
            "created_at": self._utcnow(),
        })

    def create_group(self, creator: str, group_name: str) -> Dict[str, int | str]:
        if not group_name:
            raise ValueError("Group name is required.")

        creator_doc = self.db.collection("users").document(creator).get()
        if not creator_doc.exists:
            raise ValueError("Creator does not exist.")

        group_ref = self._group_ref(group_name)
        if group_ref.get().exists:
            raise ValueError("Group already exists.")

        group_ref.set(
            {
                "name": group_name,
                "members": [creator],
                "current_key_version": 1,
                "created_by": creator,
                "created_at": self._utcnow(),
                "updated_at": self._utcnow(),
            }
        )
        self._create_group_key(group_name, [creator])
        return {"group": group_name, "key_version": 1}

    def add_member_to_group(self, requester: str, group_name: str, username_to_add: str) -> Dict[str, int | str]:
        members = self._members(group_name)
        if not members:
            raise ValueError("Group does not exist.")

        requester_doc = self.db.collection("users").document(requester).get()
        if not requester_doc.exists:
            raise ValueError("Requester does not exist.")

        if requester not in members:
            raise ValueError("Only existing group members can add new members.")

        user_doc = self.db.collection("users").document(username_to_add).get()
        if not user_doc.exists:
            raise ValueError("User to add does not exist.")

        if username_to_add in members:
            raise ValueError("User is already a group member.")

        # Add the new member to the members list
        updated_members = sorted(members + [username_to_add])
        self._group_ref(group_name).set(
            {
                "members": updated_members,
                "updated_at": self._utcnow(),
            },
            merge=True,
        )

        # Add wrapped key for the new member
        self._add_wrapped_key_for_member(group_name, username_to_add)

        return {
            "group": group_name,
            "added_user": username_to_add,
            "key_version": 1,
        }

    def remove_member_from_group(self, requester: str, group_name: str, username_to_remove: str) -> Dict[str, int | str]:
        members = self._members(group_name)
        if not members:
            raise ValueError("Group does not exist.")

        if requester not in members:
            raise ValueError("Only existing group members can remove members.")

        if username_to_remove not in members:
            raise ValueError("User is not a member of this group.")

        remaining_members = sorted([member for member in members if member != username_to_remove])
        if not remaining_members:
            raise ValueError("Cannot remove the last member from a group.")

        # Remove the member from the members list
        self._group_ref(group_name).set(
            {
                "members": remaining_members,
                "updated_at": self._utcnow(),
            },
            merge=True,
        )

        # Remove wrapped key for the member
        self._remove_wrapped_key_for_member(group_name, username_to_remove)

        return {
            "group": group_name,
            "removed_user": username_to_remove,
            "key_version": 1,
        }

    def list_usernames(self) -> List[str]:
        users_ref = self.db.collection("users")
        usernames = [doc.id for doc in users_ref.stream()]
        return sorted(usernames)

    def list_group_members_for_group(self, group_name: str) -> List[str]:
        return sorted(self._members(group_name))

    def list_groups_for_user(self, username: str) -> List[str]:
        groups = self.db.collection("groups").where("members", "array_contains", username).stream()
        return sorted([doc.id for doc in groups])

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
            "issued_at": self._utcnow(),
        })
        return token

    def get_user_by_token(self, token: str) -> str:
        session_doc = self.db.collection('sessions').document(token).get()
        if not session_doc.exists:
            raise ValueError("Invalid or expired token.")
        return session_doc.to_dict()["username"]

    def create_post(self, username: str, group_name: str | None, content: str) -> dict:
        posts_ref = self.db.collection('posts')
        existing_posts = posts_ref.stream()
        max_id = max([doc.to_dict().get('id', 0) for doc in existing_posts], default=0)
        post_id = max_id + 1

        # If no group, encrypt with author's public key
        if not group_name:
            user_doc = self.db.collection("users").document(username).get()
            if not user_doc.exists:
                raise ValueError("User does not exist.")
            
            user_data = user_doc.to_dict()
            public_key = self._load_public_key(user_data["public_key_pem"])
            
            # Generate a random AES key for this personal post
            personal_key = AESGCM.generate_key(bit_length=256)
            
            # Encrypt the AES key with the user's public key
            wrapped_key = public_key.encrypt(
                personal_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            
            # Encrypt the content with the AES key
            encrypted = self._encrypt_content(content, personal_key)
            
            post = {
                "id": post_id,
                "group": None,
                "author": username,
                "content": encrypted["ciphertext_b64"],
                "nonce_b64": encrypted["nonce_b64"],
                "ciphertext_b64": encrypted["ciphertext_b64"],
                "wrapped_key_b64": self._b64encode(wrapped_key),
                "created_at": self._utcnow(),
            }
            posts_ref.document(str(post_id)).set(post)
            return post

        # Group-based post with encryption
        members = self._members(group_name)
        if username not in members:
            raise ValueError("User is not an active member of the secure group.")

        group_doc = self._group_ref(group_name).get()
        if not group_doc.exists:
            raise ValueError("Secure group is not initialized.")

        key_version = group_doc.to_dict().get("current_key_version")
        if not key_version:
            raise ValueError("Secure group key is unavailable.")

        group_key = self._unwrap_group_key_for_user(group_name, username, key_version)
        encrypted = self._encrypt_content(content, group_key)

        post = {
            "id": post_id,
            "group": group_name,
            "author": username,
            "content": encrypted["ciphertext_b64"],
            "nonce_b64": encrypted["nonce_b64"],
            "ciphertext_b64": encrypted["ciphertext_b64"],
            "group_key_version": key_version,
            "created_at": self._utcnow(),
        }
        posts_ref.document(str(post_id)).set(post)
        return post

    def list_posts(self, username: str | None = None, group_name: str | None = None) -> List[Dict[str, str]]:
        posts_ref = self.db.collection('posts')
        if group_name:
            posts = [doc.to_dict() for doc in posts_ref.where("group", "==", group_name).stream()]
            allowed_groups = {group_name}
        elif username:
            allowed_groups = set(self.list_groups_for_user(username))
            posts = [doc.to_dict() for doc in posts_ref.stream()]
        else:
            allowed_groups = set()
            posts = []

        decrypted_posts: List[Dict[str, str]] = []
        for post in posts:
            post_group = post.get("group")
            rendered = {
                "id": post.get("id"),
                "group": post_group,
                "author": post.get("author"),
                "created_at": post.get("created_at"),
            }

            # Ungrouped posts are encrypted with author's key
            if not post_group:
                post_author = post.get("author")
                wrapped_key_b64 = post.get("wrapped_key_b64")
                
                # Only the author can decrypt their own ungrouped posts
                if username == post_author and wrapped_key_b64:
                    try:
                        user_doc = self.db.collection("users").document(username).get()
                        if user_doc.exists:
                            user_private_key = self._load_private_key(user_doc.to_dict()["private_key_pem"])
                            personal_key = user_private_key.decrypt(
                                self._b64decode(wrapped_key_b64),
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None,
                                ),
                            )
                            rendered["content"] = self._decrypt_content(
                                post["nonce_b64"],
                                post["ciphertext_b64"],
                                personal_key,
                            )
                            rendered["encrypted"] = False
                        else:
                            rendered["content"] = post.get("ciphertext_b64", "")
                            rendered["encrypted"] = True
                    except Exception:
                        rendered["content"] = post.get("ciphertext_b64", "")
                        rendered["encrypted"] = True
                else:
                    rendered["content"] = post.get("ciphertext_b64", "")
                    rendered["encrypted"] = True
                decrypted_posts.append(rendered)
                continue

            version = post.get("group_key_version")
            if not username or post_group not in allowed_groups or not version:
                rendered["content"] = post.get("ciphertext_b64", post.get("content", ""))
                rendered["encrypted"] = True
                decrypted_posts.append(rendered)
                continue

            try:
                key = self._unwrap_group_key_for_user(post_group, username, int(version))
                rendered["content"] = self._decrypt_content(
                    post["nonce_b64"],
                    post["ciphertext_b64"],
                    key,
                )
                rendered["encrypted"] = False
            except Exception:
                rendered["content"] = post.get("ciphertext_b64", post.get("content", ""))
                rendered["encrypted"] = True

            decrypted_posts.append(rendered)

        return sorted(decrypted_posts, key=lambda p: p["id"], reverse=True)

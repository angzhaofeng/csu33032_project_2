from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from src.file_store import TextBackedStore

app = FastAPI(title="Secure Social Web API", version="0.1.0")
store = TextBackedStore("firebase.json")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    
    # allow_origins=["*"],
    # allow_credentials=False,
    
    allow_methods=["*"],
    allow_headers=["*"],
)


class SignupRequest(BaseModel):
    username: str = Field(min_length=3, max_length=30)
    password: str = Field(min_length=6, max_length=128)


class LoginRequest(BaseModel):
    username: str
    password: str


class CreatePostRequest(BaseModel):
    group_name: str = Field(min_length=1, max_length=64)
    content: str = Field(min_length=1, max_length=1000)


class AddGroupMemberRequest(BaseModel):
    group_name: str = Field(min_length=1, max_length=64)
    username: str = Field(min_length=3, max_length=30)


class CreateGroupRequest(BaseModel):
    group_name: str = Field(min_length=1, max_length=64)


class AuthResponse(BaseModel):
    token: str
    username: str


def _extract_bearer_token(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header.")

    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Authorization must use Bearer token.")
    return parts[1].strip()


def get_current_user(authorization: str | None = Header(default=None)) -> str:
    token = _extract_bearer_token(authorization)
    try:
        return store.get_user_by_token(token)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/auth/signup", status_code=201)
def signup(payload: SignupRequest) -> dict:
    try:
        store.create_user(payload.username.strip(), payload.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"message": "User created successfully."}


@app.post("/auth/login", response_model=AuthResponse)
def login(payload: LoginRequest) -> AuthResponse:
    try:
        token = store.authenticate_user(payload.username.strip(), payload.password)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    return AuthResponse(token=token, username=payload.username.strip())


@app.get("/posts")
def get_posts(
    username: str = Depends(get_current_user),
    group_name: str | None = Query(default=None),
) -> dict:
    return {"posts": store.list_posts(username=username, group_name=group_name)}


@app.get("/groups")
def get_groups(username: str = Depends(get_current_user)) -> dict:
    return {"groups": store.list_groups_for_user(username)}


@app.post("/groups", status_code=201)
def create_group(payload: CreateGroupRequest, requester: str = Depends(get_current_user)) -> dict:
    try:
        result = store.create_group(creator=requester, group_name=payload.group_name.strip())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"message": "Group created.", "group": result}


@app.get("/users")
def get_users(group_name: str, _: str = Depends(get_current_user)) -> dict:
    return {
        "users": store.list_usernames(),
        "group_members": store.list_group_members_for_group(group_name),
    }


@app.post("/posts", status_code=201)
def create_post(payload: CreatePostRequest, username: str = Depends(get_current_user)) -> dict:
    try:
        post = store.create_post(
            username=username,
            group_name=payload.group_name.strip(),
            content=payload.content.strip(),
        )
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return {"post": post}


@app.post("/groups/members", status_code=201)
def add_group_member(payload: AddGroupMemberRequest, requester: str = Depends(get_current_user)) -> dict:
    try:
        result = store.add_member_to_group(
            requester=requester,
            group_name=payload.group_name.strip(),
            username_to_add=payload.username.strip(),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"message": "Member added to secure group.", "group": result}

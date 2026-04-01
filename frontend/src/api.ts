import type { Post } from "./types";

const API_BASE = "http://127.0.0.1:8000";

interface ApiErrorPayload {
  detail?: string;
}

async function parseOrThrow(response: Response) {
  const body = (await response.json()) as ApiErrorPayload;
  if (!response.ok) {
    throw new Error(body.detail ?? "Request failed.");
  }
  return body;
}

export async function signup(username: string, password: string): Promise<void> {
  const response = await fetch(`${API_BASE}/auth/signup`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });

  await parseOrThrow(response);
}

export async function login(username: string, password: string): Promise<string> {
  const response = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });

  const data = (await parseOrThrow(response)) as { token: string };
  return data.token;
}

export async function fetchPosts(token: string): Promise<Post[]> {
  const response = await fetch(`${API_BASE}/posts`, {
    headers: { Authorization: `Bearer ${token}` },
  });

  const data = (await parseOrThrow(response)) as { posts: Post[] };
  return data.posts;
}

export async function createPost(token: string, content: string): Promise<void> {
  const response = await fetch(`${API_BASE}/posts`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ content }),
  });

  await parseOrThrow(response);
}

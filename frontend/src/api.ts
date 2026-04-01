import type { Post } from "./types";

const API_BASE = "http://127.0.0.1:8000";

interface ApiErrorPayload {
  detail?: unknown;
}

async function parseOrThrow(response: Response) {
  const contentType = response.headers.get("content-type") ?? "";
  const isJson = contentType.includes("application/json");
  const body = isJson ? ((await response.json()) as ApiErrorPayload) : null;

  if (!response.ok) {
    const detail = body?.detail;
    if (typeof detail === "string") {
      throw new Error(detail);
    }
    if (Array.isArray(detail)) {
      const message = detail
        .map((item) => {
          if (typeof item === "string") {
            return item;
          }
          if (item && typeof item === "object" && "msg" in item && typeof item.msg === "string") {
            return item.msg;
          }
          return JSON.stringify(item);
        })
        .join("; ");
      throw new Error(message || "Request failed.");
    }
    if (detail && typeof detail === "object") {
      throw new Error(JSON.stringify(detail));
    }
    if (!isJson) {
      const text = await response.text();
      throw new Error(text || "Request failed.");
    }
    throw new Error("Request failed.");
  }

  return body ?? {};
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

export async function fetchPostsForGroup(token: string, groupName: string): Promise<Post[]> {
  const response = await fetch(`${API_BASE}/posts?group_name=${encodeURIComponent(groupName)}`, {
    headers: { Authorization: `Bearer ${token}` },
  });

  const data = (await parseOrThrow(response)) as { posts: Post[] };
  return data.posts;
}

export async function createPost(token: string, groupName: string, content: string): Promise<void> {
  const response = await fetch(`${API_BASE}/posts`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ group_name: groupName, content }),
  });

  await parseOrThrow(response);
}

export async function addGroupMemberToGroup(token: string, groupName: string, username: string): Promise<void> {
  const response = await fetch(`${API_BASE}/groups/members`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ group_name: groupName, username }),
  });

  await parseOrThrow(response);
}

export async function removeGroupMemberFromGroup(token: string, groupName: string, username: string): Promise<void> {
  const response = await fetch(`${API_BASE}/groups/members/remove`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ group_name: groupName, username }),
  });

  await parseOrThrow(response);
}

export async function fetchUsers(token: string, groupName: string): Promise<{ users: string[]; group_members: string[] }> {
  const response = await fetch(`${API_BASE}/users?group_name=${encodeURIComponent(groupName)}`, {
    headers: { Authorization: `Bearer ${token}` },
  });

  return (await parseOrThrow(response)) as { users: string[]; group_members: string[] };
}

export async function fetchGroups(token: string): Promise<string[]> {
  const response = await fetch(`${API_BASE}/groups`, {
    headers: { Authorization: `Bearer ${token}` },
  });

  const data = (await parseOrThrow(response)) as { groups: string[] };
  return data.groups;
}

export async function createGroup(token: string, groupName: string): Promise<void> {
  const response = await fetch(`${API_BASE}/groups`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ group_name: groupName }),
  });

  await parseOrThrow(response);
}

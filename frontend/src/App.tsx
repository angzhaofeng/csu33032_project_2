import { FormEvent, useEffect, useMemo, useState } from "react";
import { createPost, fetchPosts, login, signup } from "./api";
import type { AuthMode, Post } from "./types";

const TOKEN_KEY = "secure_social_token";
const USER_KEY = "secure_social_user";

function formatTimestamp(timestamp: string): string {
  return new Date(timestamp).toLocaleString();
}

export default function App() {
  const [mode, setMode] = useState<AuthMode>("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const [posts, setPosts] = useState<Post[]>([]);
  const [token, setToken] = useState<string>(() => localStorage.getItem(TOKEN_KEY) ?? "");
  const [currentUser, setCurrentUser] = useState<string>(() => localStorage.getItem(USER_KEY) ?? "");

  const isLoggedIn = useMemo(() => token.length > 0, [token]);

  async function loadPosts(activeToken: string) {
    try {
      const data = await fetchPosts(activeToken);
      setPosts(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load posts.");
    }
  }

  useEffect(() => {
    if (token) {
      void loadPosts(token);
    }
  }, [token]);

  async function handleAuthSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setInfo("");

    try {
      if (mode === "signup") {
        await signup(username, password);
        setInfo("Signup successful. You can now log in.");
        setMode("login");
        return;
      }

      const nextToken = await login(username, password);
      localStorage.setItem(TOKEN_KEY, nextToken);
      localStorage.setItem(USER_KEY, username);
      setToken(nextToken);
      setCurrentUser(username);
      setPassword("");
      setInfo("Welcome back.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Authentication failed.");
    }
  }

  async function handleCreatePost(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!message.trim()) {
      return;
    }

    setError("");
    setInfo("");

    try {
      await createPost(token, message.trim());
      setMessage("");
      await loadPosts(token);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to publish post.");
    }
  }

  function handleLogout() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    setToken("");
    setCurrentUser("");
    setPosts([]);
    setInfo("You have logged out.");
  }

  return (
    <main className="page-shell">
      <div className="grain" />
      {!isLoggedIn ? (
        <section className="auth-card">
          <p className="eyebrow">Secure Social</p>
          <h1>{mode === "login" ? "Sign in" : "Create account"}</h1>
          <p className="subtitle">Join the campus discussion board with your own account.</p>

          <form className="auth-form" onSubmit={handleAuthSubmit}>
            <label htmlFor="username">Username</label>
            <input
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="your-name"
              required
              minLength={3}
            />

            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="at least 6 characters"
              required
              minLength={6}
            />

            <button type="submit">{mode === "login" ? "Login" : "Sign up"}</button>
          </form>

          {error && <p className="error-text">{error}</p>}
          {info && <p className="info-text">{info}</p>}

          <button className="switch-link" onClick={() => setMode(mode === "login" ? "signup" : "login")}>
            {mode === "login" ? "Need an account? Sign up" : "Already registered? Log in"}
          </button>
        </section>
      ) : (
        <section className="board-wrap">
          <header className="board-header">
            <div>
              <p className="eyebrow">Discussion Board</p>
              <h1>Home feed</h1>
              <p className="subtitle">Signed in as {currentUser}</p>
            </div>
            <button className="secondary" onClick={handleLogout}>
              Logout
            </button>
          </header>

          <form className="post-form" onSubmit={handleCreatePost}>
            <textarea
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="Share something with your group..."
              maxLength={1000}
            />
            <button type="submit">Post</button>
          </form>

          {error && <p className="error-text">{error}</p>}
          {info && <p className="info-text">{info}</p>}

          <div className="post-list">
            {posts.length === 0 && <p className="empty-state">No posts yet. Start the discussion.</p>}
            {posts.map((post) => (
              <article key={post.id} className="post-card">
                <div className="post-head">
                  <strong>{post.author}</strong>
                  <span>{formatTimestamp(post.created_at)}</span>
                </div>
                <p>{post.content}</p>
              </article>
            ))}
          </div>
        </section>
      )}
    </main>
  );
}

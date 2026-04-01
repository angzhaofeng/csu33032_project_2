import { FormEvent, useEffect, useMemo, useState } from "react";
import {
  addGroupMemberToGroup,
  createGroup,
  createPost,
  fetchGroups,
  fetchPosts,
  fetchUsers,
  login,
  removeGroupMemberFromGroup,
  signup,
} from "./api";
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
  const [newGroupName, setNewGroupName] = useState("");
  const [selectedGroup, setSelectedGroup] = useState("");
  const [memberUsername, setMemberUsername] = useState("");
  const [memberToRemove, setMemberToRemove] = useState("");
  const [memberOptions, setMemberOptions] = useState<string[]>([]);
  const [removeMemberOptions, setRemoveMemberOptions] = useState<string[]>([]);
  const [groups, setGroups] = useState<string[]>([]);
  const [isComposerOpen, setIsComposerOpen] = useState(false);
  const [isGroupModalOpen, setIsGroupModalOpen] = useState(false);
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const [posts, setPosts] = useState<Post[]>([]);
  const [token, setToken] = useState<string>(() => localStorage.getItem(TOKEN_KEY) ?? "");
  const [currentUser, setCurrentUser] = useState<string>(() => localStorage.getItem(USER_KEY) ?? "");

  const isLoggedIn = useMemo(() => token.length > 0, [token]);

  async function loadGroups(activeToken: string) {
    const groupList = await fetchGroups(activeToken);
    setGroups(groupList);

    if (groupList.length === 0) {
      setSelectedGroup("");
      return;
    }

    setSelectedGroup((prev) => (prev && groupList.includes(prev) ? prev : groupList[0]));
  }

  async function loadPosts(activeToken: string) {
    try {
      const data = await fetchPosts(activeToken);
      setPosts(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load posts.");
    }
  }

  async function loadMemberOptions(activeToken: string, groupName: string) {
    if (!groupName) {
      setMemberOptions([]);
      setMemberUsername("");
      return;
    }

    try {
      const data = await fetchUsers(activeToken, groupName);
      const options = data.users.filter(
        (candidate) => candidate !== currentUser && !data.group_members.includes(candidate)
      );
      const removable = data.group_members.filter((candidate) => candidate !== currentUser);

      setMemberOptions(options);
      setRemoveMemberOptions(removable);

      if (!options.includes(memberUsername)) {
        setMemberUsername(options[0] ?? "");
      }
      if (!removable.includes(memberToRemove)) {
        setMemberToRemove(removable[0] ?? "");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load users.");
    }
  }

  useEffect(() => {
    if (!token) {
      return;
    }

    void (async () => {
      try {
        await loadGroups(token);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Could not load groups.");
      }
    })();
  }, [token]);

  useEffect(() => {
    if (!token) {
      setPosts([]);
      return;
    }

    void loadPosts(token);
    if (selectedGroup) {
      void loadMemberOptions(token, selectedGroup);
    } else {
      setMemberOptions([]);
      setMemberUsername("");
      setRemoveMemberOptions([]);
      setMemberToRemove("");
    }
  }, [token, selectedGroup, currentUser]);

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

  async function handleCreateGroup(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!newGroupName.trim()) {
      return;
    }

    setError("");
    setInfo("");

    try {
      const nextGroup = newGroupName.trim();
      await createGroup(token, nextGroup);
      await loadGroups(token);
      setSelectedGroup(nextGroup);
      setNewGroupName("");
      setInfo(`Created group ${nextGroup}.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create group.");
    }
  }

  async function handleCreatePost(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!message.trim() || !selectedGroup) {
      return;
    }

    setError("");
    setInfo("");

    try {
      await createPost(token, selectedGroup, message.trim());
      setMessage("");
      await loadPosts(token);
      setIsComposerOpen(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to publish post.");
    }
  }

  async function handleAddMember(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!memberUsername.trim() || !selectedGroup) {
      return;
    }

    setError("");
    setInfo("");

    try {
      await addGroupMemberToGroup(token, selectedGroup, memberUsername.trim());
      setInfo(`Added ${memberUsername.trim()} to group ${selectedGroup}.`);
      await loadMemberOptions(token, selectedGroup);
      await loadPosts(token);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to add member.");
    }
  }

  async function handleRemoveMember(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!memberToRemove.trim() || !selectedGroup) {
      return;
    }

    setError("");
    setInfo("");

    try {
      await removeGroupMemberFromGroup(token, selectedGroup, memberToRemove.trim());
      setInfo(`Removed ${memberToRemove.trim()} from group ${selectedGroup}.`);
      await loadMemberOptions(token, selectedGroup);
      await loadPosts(token);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to remove member.");
    }
  }

  function handleLogout() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    setToken("");
    setCurrentUser("");
    setGroups([]);
    setSelectedGroup("");
    setPosts([]);
    setIsComposerOpen(false);
    setIsGroupModalOpen(false);
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
            <div className="board-actions">
              <button className="primary-action" onClick={() => setIsComposerOpen(true)}>
                Add Post
              </button>
              <button className="primary-action" onClick={() => setIsGroupModalOpen(true)}>
                Group
              </button>
              <button className="secondary" onClick={handleLogout}>
                Logout
              </button>
            </div>
          </header>

          {error && <p className="error-text">{error}</p>}
          {info && <p className="info-text">{info}</p>}

          <div className="post-list">
            {posts.length === 0 && <p className="empty-state">No posts yet for this group. Start the discussion.</p>}
            {posts.map((post) => (
              <article key={post.id} className="post-card">
                <div className="post-head">
                  <strong>{post.author}</strong>
                  <span>{formatTimestamp(post.created_at)}</span>
                </div>
                <p className="group-tag">{post.encrypted ? `` : `Group: ${post.group}`}</p>
                <p className={post.encrypted ? "post-tag post-tag-encrypted" : "post-tag post-tag-clear"}>
                  {post.encrypted ? "Encrypted (not decryptable with your key)" : "Decrypted for your group access"}
                </p>
                <p>{post.content}</p>
              </article>
            ))}
          </div>

          {isComposerOpen && (
            <div className="modal-overlay" onClick={() => setIsComposerOpen(false)}>
              <section className="modal-card" onClick={(e) => e.stopPropagation()}>
                <header className="modal-header">
                  <h2>Add Post</h2>
                  <button className="secondary" onClick={() => setIsComposerOpen(false)}>
                    Close
                  </button>
                </header>

                <div className="group-picker">
                  <label htmlFor="group-select">Current Group</label>
                  <select
                    id="group-select"
                    value={selectedGroup}
                    onChange={(e) => setSelectedGroup(e.target.value)}
                    disabled={groups.length === 0}
                  >
                    {groups.length === 0 ? (
                      <option value="">No groups yet. Create one.</option>
                    ) : (
                      groups.map((group) => (
                        <option key={group} value={group}>
                          {group}
                        </option>
                      ))
                    )}
                  </select>
                </div>

                {/* <form className="member-form" onSubmit={handleAddMember}>
                  <label htmlFor="member-username">Add Member To Current Group</label>
                  <div className="member-row">
                    <select
                      id="member-username"
                      value={memberUsername}
                      onChange={(e) => setMemberUsername(e.target.value)}
                      required
                      disabled={memberOptions.length === 0 || !selectedGroup}
                    >
                      {memberOptions.length === 0 ? (
                        <option value="">No available users to add</option>
                      ) : (
                        memberOptions.map((candidate) => (
                          <option key={candidate} value={candidate}>
                            {candidate}
                          </option>
                        ))
                      )}
                    </select>
                    <button type="submit" disabled={memberOptions.length === 0 || !selectedGroup}>
                      Add member
                    </button>
                  </div>
                </form>

                <form className="member-form" onSubmit={handleRemoveMember}>
                  <label htmlFor="member-remove">Remove Member From Current Group</label>
                  <div className="member-row">
                    <select
                      id="member-remove"
                      value={memberToRemove}
                      onChange={(e) => setMemberToRemove(e.target.value)}
                      required
                      disabled={removeMemberOptions.length === 0 || !selectedGroup}
                    >
                      {removeMemberOptions.length === 0 ? (
                        <option value="">No removable members in this group</option>
                      ) : (
                        removeMemberOptions.map((candidate) => (
                          <option key={candidate} value={candidate}>
                            {candidate}
                          </option>
                        ))
                      )}
                    </select>
                    <button type="submit" disabled={removeMemberOptions.length === 0 || !selectedGroup}>
                      Remove member
                    </button>
                  </div>
                </form> */}

                <form className="post-form" onSubmit={handleCreatePost}>
                  <textarea
                    value={message}
                    onChange={(e) => setMessage(e.target.value)}
                    placeholder={selectedGroup ? `Share to ${selectedGroup}...` : "Create/select a group first."}
                    maxLength={1000}
                    disabled={!selectedGroup}
                  />
                  <button type="submit" disabled={!selectedGroup}>
                    Post
                  </button>
                </form>
              </section>
            </div>
          )}

          {isGroupModalOpen && (
            <div className="modal-overlay" onClick={() => setIsGroupModalOpen(false)}>
              <section className="modal-card" onClick={(e) => e.stopPropagation()}>
                <header className="modal-header">
                  <h2>Group Management</h2>
                  <button className="secondary" onClick={() => setIsGroupModalOpen(false)}>
                    Close
                  </button>
                </header>

                <form className="group-form" onSubmit={handleCreateGroup}>
                  <label htmlFor="group-name">Create Group</label>
                  <div className="member-row">
                    <input
                      id="group-name"
                      value={newGroupName}
                      onChange={(e) => setNewGroupName(e.target.value)}
                      placeholder="e.g. csu-team"
                      minLength={1}
                      maxLength={64}
                      required
                    />
                    <button type="submit">Create group</button>
                  </div>
                </form>

                <div className="group-picker">
                  <label htmlFor="group-select-manage">Current Group</label>
                  <select
                    id="group-select-manage"
                    value={selectedGroup}
                    onChange={(e) => setSelectedGroup(e.target.value)}
                    disabled={groups.length === 0}
                  >
                    {groups.length === 0 ? (
                      <option value="">No groups yet. Create one.</option>
                    ) : (
                      groups.map((group) => (
                        <option key={group} value={group}>
                          {group}
                        </option>
                      ))
                    )}
                  </select>
                </div>

                <form className="member-form" onSubmit={handleAddMember}>
                  <label htmlFor="member-username">Add Member To Current Group</label>
                  <div className="member-row">
                    <select
                      id="member-username"
                      value={memberUsername}
                      onChange={(e) => setMemberUsername(e.target.value)}
                      required
                      disabled={memberOptions.length === 0 || !selectedGroup}
                    >
                      {memberOptions.length === 0 ? (
                        <option value="">No available users to add</option>
                      ) : (
                        memberOptions.map((candidate) => (
                          <option key={candidate} value={candidate}>
                            {candidate}
                          </option>
                        ))
                      )}
                    </select>
                    <button type="submit" disabled={memberOptions.length === 0 || !selectedGroup}>
                      Add member
                    </button>
                  </div>
                </form>

                <form className="member-form" onSubmit={handleRemoveMember}>
                  <label htmlFor="member-remove">Remove Member From Current Group</label>
                  <div className="member-row">
                    <select
                      id="member-remove"
                      value={memberToRemove}
                      onChange={(e) => setMemberToRemove(e.target.value)}
                      required
                      disabled={removeMemberOptions.length === 0 || !selectedGroup}
                    >
                      {removeMemberOptions.length === 0 ? (
                        <option value="">No removable members in this group</option>
                      ) : (
                        removeMemberOptions.map((candidate) => (
                          <option key={candidate} value={candidate}>
                            {candidate}
                          </option>
                        ))
                      )}
                    </select>
                    <button type="submit" disabled={removeMemberOptions.length === 0 || !selectedGroup}>
                      Remove member
                    </button>
                  </div>
                </form>
              </section>
            </div>
          )}
        </section>
      )}
    </main>
  );
}

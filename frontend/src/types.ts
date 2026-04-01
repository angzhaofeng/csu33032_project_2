export type AuthMode = "login" | "signup";

export interface Post {
  id: number;
  group: string;
  author: string;
  content: string;
  created_at: string;
  encrypted?: boolean;
}

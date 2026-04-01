export type AuthMode = "login" | "signup";

export interface Post {
  id: number;
  author: string;
  content: string;
  created_at: string;
}

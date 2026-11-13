// Users and passwords (DR-041; contracts/openapi.yaml /api/v1/users and /api/v1/auth/password). Passwords are sent in the request body only, held in component
// state until the request is made, and never stored, logged or shown again.
import { exchange, read } from "./client";
import { decoderFor } from "./decoders";
import { csrfToken } from "./session";
import type { AuthSession, User, UserList } from "./schema";

export const decodeUser = decoderFor<User>("User");
export const decodeUserList = decoderFor<UserList>("UserList");
const decodeSession = decoderFor<AuthSession>("AuthSession");

export type Role = User["role"];

export const listUsers = () => read("/api/v1/users", decodeUserList);
export const changePassword = (current: string, next: string) =>
  exchange("POST", "/api/v1/auth/password", decodeSession, { body: { current_password: current, new_password: next }, csrf: csrfToken() });
export const createUser = (username: string, role: Role, password: string) => exchange("POST", "/api/v1/users", decodeUser, { body: { username, role, password }, csrf: csrfToken() });
export const setUserRole = (name: string, role: Role) => exchange("POST", `/api/v1/users/${name}/role`, decodeUser, { body: { role }, csrf: csrfToken() });
export const setUserDisabled = (name: string, disabled: boolean) => exchange("POST", `/api/v1/users/${name}/${disabled ? "disable" : "enable"}`, decodeUser, { csrf: csrfToken() });
export const resetUserPassword = (name: string, password: string) => exchange("POST", `/api/v1/users/${name}/password`, decodeUser, { body: { password }, csrf: csrfToken() });

// The signed-in user's role (DR-023 D1). The server decides and enforces; this only hides what the role cannot do, so a viewer is not offered a button that would be refused.
import { createContext, useContext } from "react";

export type Role = "admin" | "operator" | "viewer";
export const RoleContext = createContext<Role | null>(null);
export const useRole = (): Role | null => useContext(RoleContext);

const RANK: Record<Role, number> = { viewer: 1, operator: 2, admin: 3 };
export function atLeast(role: Role | null, min: Role): boolean { return role !== null && RANK[role] >= RANK[min]; }

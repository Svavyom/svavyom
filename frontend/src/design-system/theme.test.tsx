import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AppShell } from "./layout";

afterEach(() => { cleanup(); document.documentElement.removeAttribute("data-theme"); });

describe("theme switch", () => {
  it("cycles System, Light, Dark and sets data-theme only for an explicit choice", async () => {
    render(<AppShell nav={[{ href: "#/", label: "Dashboard", current: true, icon: "dashboard" }]} user="admin"><p>x</p></AppShell>);
    const root = document.documentElement;
    expect(root.getAttribute("data-theme")).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: /Theme: System/ }));
    expect(root.getAttribute("data-theme")).toBe("light");
    await userEvent.click(screen.getByRole("button", { name: /Theme: Light/ }));
    expect(root.getAttribute("data-theme")).toBe("dark");
    await userEvent.click(screen.getByRole("button", { name: /Theme: Dark/ }));
    expect(root.getAttribute("data-theme")).toBeNull();
  });

  it("shows who is signed in and keeps the navigation labelled", () => {
    render(<AppShell nav={[{ href: "#/", label: "Dashboard", current: true }]} user="admin"><p>x</p></AppShell>);
    expect(screen.getByText("Signed in as")).toBeTruthy();
    expect(screen.getByRole("navigation", { name: "Primary" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "Dashboard" }).getAttribute("aria-current")).toBe("page");
  });

  it("never touches browser storage", async () => {
    render(<AppShell nav={[]}><p>x</p></AppShell>);
    await userEvent.click(screen.getByRole("button", { name: /Theme: System/ }));
    expect(JSON.stringify(localStorage) + JSON.stringify(sessionStorage) + document.cookie).toBe("{}{}");
  });
});

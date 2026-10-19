// fe-unit: every manifest state renders with role, accessible name and state; axe (jsdom tier) finds no
// violations; keyboard and focus rules that jsdom can exercise (M0-E02-S06 AC01).
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen, within, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import manifest from "./states.json";
import { RENDERERS } from "../gallery/states";
import { Gallery } from "../gallery/Gallery";
import { AppShell, Button, Dialog, ErrorSummary, StatusMessage, Alert, Tabs, TextField, ViewHeading } from ".";
import { axeViolations } from "../test-axe";
import { useState } from "react";

afterEach(cleanup);

const STATES = Object.entries(manifest.primitives).flatMap(([p, ss]) => ss.map((s) => [p, s] as const));

function renderState(p: string, s: string) {
  location.hash = `#/state/${p}/${s}`;
  return render(<Gallery />);
}

describe("design-system primitives", () => {
  it("gallery renders every manifest state", () => {
    for (const [p, s] of STATES) {
      expect(RENDERERS[p]?.[s], `${p}/${s} renderer`).toBeTypeOf("function");
      const { unmount, container } = renderState(p, s);
      expect(container.textContent).not.toContain("Unknown state");
      unmount();
    }
  });

  it("every manifest state renders with an accessible role and name", () => {
    for (const [p, s] of STATES) {
      const { unmount } = renderState(p, s);
      expect(screen.getByRole("main")).toBeTruthy();
      expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
      for (const el of document.querySelectorAll<HTMLElement>("button, a[href], input, select, textarea, [role=tab], [role=dialog]")) {
        const name = el.getAttribute("aria-label") || el.getAttribute("aria-labelledby") || el.textContent?.trim()
          || (el.id && document.querySelector(`label[for="${el.id}"]`)?.textContent) || el.closest("label")?.textContent;
        expect(name, `${p}/${s}: ${el.outerHTML.slice(0, 80)} needs a name`).toBeTruthy();
      }
      unmount();
    }
  });

  it("axe finds no violations in the jsdom tier on every manifest state", async () => {
    for (const [p, s] of STATES) {
      const { unmount } = renderState(p, s);
      expect(await axeViolations(document.body), `${p}/${s}`).toEqual([]);
      unmount();
    }
  }, 120000);

  it("invalid and disabled states are conveyed without colour alone", () => {
    render(<><TextField label="Name" value="" onChange={() => undefined} error="Enter a name" /><Button disabled>Go</Button></>);
    const input = screen.getByLabelText(/Name/);
    expect(input.getAttribute("aria-invalid")).toBe("true");
    expect(document.getElementById(input.getAttribute("aria-describedby")!.split(" ").pop()!)?.textContent).toContain("Enter a name");
    expect(screen.getByRole("button", { name: "Go" }).getAttribute("aria-disabled")).toBe("true");
  });

  it("accessible names contain the visible labels", () => {
    for (const [p, s] of STATES) {
      const { unmount } = renderState(p, s);
      for (const b of document.querySelectorAll<HTMLElement>("button[aria-label]")) {
        expect(b.getAttribute("aria-label")!.toLowerCase()).toContain((b.textContent ?? "").trim().toLowerCase());
      }
      unmount();
    }
  });

  it("inputs do not collect personal data without an autocomplete purpose", () => {
    for (const [p, s] of STATES) {
      const { unmount } = renderState(p, s);
      for (const i of document.querySelectorAll("input")) {
        // M0 has no personal-data inputs; every text input must still declare its purpose explicitly
        // ("off" for product data such as VM names), so a personal-data field cannot appear without one.
        if (["text", "email", "tel", "password"].includes(i.type)) {
          expect(i.getAttribute("autocomplete"), `${p}/${s}: ${i.outerHTML.slice(0, 60)}`).toMatch(/^(off|[a-z-]+( [a-z-]+)*)$/);
        }
        if (["email", "tel", "password"].includes(i.type)) expect(i.getAttribute("autocomplete")).not.toBe("off");
      }
      unmount();
    }
  });

  it("skip link moves focus to main", async () => {
    render(<AppShell nav={[]}><p>x</p></AppShell>);
    await userEvent.tab();
    expect(document.activeElement?.textContent).toBe("Skip to main content");
    await userEvent.keyboard("{Enter}");
    expect(document.activeElement?.id).toBe("main");
  });

  it("view heading sets the document title and takes focus", () => {
    render(<ViewHeading title="Dashboard" />);
    expect(document.title).toBe("Dashboard - Svavyom");
    expect(document.activeElement?.tagName).toBe("H1");
  });

  it("tabs use one tab stop and arrow, Home and End keys", async () => {
    render(<Tabs label="Details" tabs={[{ id: "a", label: "A", panel: "pa" }, { id: "b", label: "B", panel: "pb" }, { id: "c", label: "C", panel: "pc" }]} />);
    const tabs = screen.getAllByRole("tab");
    expect(tabs.map((t) => t.tabIndex)).toEqual([0, -1, -1]);
    tabs[0].focus();
    await userEvent.keyboard("{ArrowRight}");
    expect(document.activeElement).toBe(tabs[1]);
    expect(tabs[1].getAttribute("aria-selected")).toBe("true");
    await userEvent.keyboard("{End}");
    expect(document.activeElement).toBe(tabs[2]);
    await userEvent.keyboard("{Home}");
    expect(document.activeElement).toBe(tabs[0]);
    await userEvent.keyboard("{ArrowLeft}");
    expect(document.activeElement).toBe(tabs[2]);
  });

  it("dialog moves focus in, contains it, closes on Escape and returns focus", async () => {
    function Harness() {
      const [open, setOpen] = useState(false);
      return (
        <>
          <button onClick={() => setOpen(true)}>Open</button>
          <Dialog title="Rename" open={open} onClose={() => setOpen(false)}><button>Inside</button></Dialog>
        </>
      );
    }
    render(<Harness />);
    const opener = screen.getByRole("button", { name: "Open" });
    await userEvent.click(opener);
    expect(document.activeElement?.textContent).toBe("Rename");
    await userEvent.tab();
    expect(document.activeElement?.textContent).toBe("Inside");
    await userEvent.tab();
    expect(document.activeElement?.textContent).toBe("Inside");
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(opener);
  });

  it("error summary lists errors and links to fields", async () => {
    render(<><ErrorSummary errors={[{ fieldId: "n", message: "Enter a name" }]} /><TextField id="n" label="Name" value="" onChange={() => undefined} error="Enter a name" /></>);
    const summary = screen.getByRole("alert");
    expect(document.activeElement).toBe(summary);
    await userEvent.click(within(summary).getByRole("link", { name: "Enter a name" }));
    expect(document.activeElement?.id).toBe("n");
  });

  it("status and alert messages use live roles", () => {
    render(<><StatusMessage>Saved</StatusMessage><Alert title="Failed" /></>);
    expect(screen.getByRole("status").textContent).toBe("Saved");
    expect(screen.getByRole("alert").textContent).toContain("Failed");
  });

  it("pending buttons keep focus, ignore activation and are announced busy", async () => {
    let clicks = 0;
    render(<Button pending onClick={() => { clicks += 1; }}>Create</Button>);
    const b = screen.getByRole("button", { name: /Create/ });
    b.focus();
    await userEvent.keyboard("{Enter}");
    await userEvent.click(b);
    expect(clicks).toBe(0);
    expect(document.activeElement).toBe(b);
    expect(b.getAttribute("aria-busy")).toBe("true");
  });

  it("loading text is immediate and the visual indicator appears after 300 ms", async () => {
    const { LoadingRegion } = await import("./feedback");
    render(<LoadingRegion label="VMs" loading />);
    expect(screen.getByRole("status").textContent).toContain("Loading vms");
    expect(screen.queryByTestId("loading-indicator")).toBeNull();
    await act(async () => { await new Promise((r) => setTimeout(r, 350)); });
    expect(screen.getByTestId("loading-indicator")).toBeTruthy();
    expect(document.querySelector("[aria-busy=true]")).toBeTruthy();
  });
});

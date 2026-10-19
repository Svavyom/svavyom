// TEST-ONLY entry for the gallery bundle (vite build --mode gallery). __GALLERY_MARKER__ lets the bundle check
// prove this code never reaches the production dist/.
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "../design-system/design-system.css";
import { Gallery } from "./Gallery";

export const GALLERY_MARKER = "__GALLERY_MARKER__ test-only fixtures";
const root = document.getElementById("root");
if (!root) throw new Error("Missing root element");
root.setAttribute("data-build", GALLERY_MARKER);
createRoot(root).render(<StrictMode><Gallery /></StrictMode>);

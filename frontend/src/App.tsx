// Production shell: the signed-in product (sign in, dashboard, sign out). Same-origin API: the control-plane process
// serves this bundle (`api serve --static-dir`), so cookies and the CSRF header stay on one origin.
import { Root } from "./product/Root";

export function App() {
  return <Root />;
}

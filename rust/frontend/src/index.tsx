/* @refresh reload */
import { render } from "solid-js/web";
import { Router, Route } from "@solidjs/router";
import App from "./App";
import { routes } from "./router";
import "./styles/global.css";
// Initialise theme on load
import "./stores/theme";

const root = document.getElementById("root");

render(
  () => (
    <Router root={App}>
      {routes.map((r) => (
        <Route path={r.path} component={r.component} />
      ))}
    </Router>
  ),
  root!,
);

import { useLocation } from "@solidjs/router";

export default function Placeholder() {
  const location = useLocation();
  const title = () => {
    const path = location.pathname.slice(1);
    return path.charAt(0).toUpperCase() + path.slice(1);
  };

  return (
    <div style={{ padding: "32px" }}>
      <h2>{title()}</h2>
      <p class="text-muted" style={{ "margin-top": "8px" }}>
        Coming soon
      </p>
    </div>
  );
}

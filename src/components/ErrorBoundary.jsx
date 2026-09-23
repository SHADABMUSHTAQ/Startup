import React from "react";

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError() {
    return { hasError: true };
  }

  componentDidCatch(error, info) {
    if (import.meta.env.DEV) {
      console.error("React render failure:", error, info);
    }
  }

  render() {
    if (this.state.hasError) {
      return (
        <main
          style={{
            minHeight: "100vh",
            display: "grid",
            placeItems: "center",
            padding: "24px",
            background: "#07111f",
            color: "#e6f1ff",
            fontFamily: "Inter, system-ui, sans-serif",
          }}
        >
          <section
            style={{
              width: "100%",
              maxWidth: "520px",
              border: "1px solid rgba(255,255,255,0.12)",
              borderRadius: "12px",
              padding: "28px",
              background: "rgba(10, 24, 42, 0.92)",
              boxShadow: "0 24px 70px rgba(0,0,0,0.35)",
            }}
          >
            <h1 style={{ margin: "0 0 12px", fontSize: "24px" }}>Something went wrong</h1>
            <p style={{ margin: "0 0 20px", color: "#a6b8c8", lineHeight: 1.6 }}>
              The dashboard hit an unexpected display error. Refresh the page to reload the session.
            </p>
            <button
              type="button"
              onClick={() => window.location.reload()}
              style={{
                border: "none",
                borderRadius: "8px",
                padding: "11px 16px",
                background: "#49aff1",
                color: "#04101f",
                fontWeight: 700,
                cursor: "pointer",
              }}
            >
              Refresh page
            </button>
          </section>
        </main>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;

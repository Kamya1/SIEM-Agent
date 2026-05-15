/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["IBM Plex Sans", "system-ui", "sans-serif"],
        mono: ["IBM Plex Mono", "ui-monospace", "monospace"],
      },
      colors: {
        void: { DEFAULT: "#070a0f", 50: "#121826", 100: "#1a2234" },
        cyan: { glow: "#22d3ee", muted: "#0891b2" },
        amber: { alert: "#fbbf24" },
      },
      boxShadow: {
        panel: "0 0 0 1px rgba(34,211,238,0.12), 0 24px 80px rgba(0,0,0,0.55)",
      },
    },
  },
  plugins: [],
};

import type { Config } from "tailwindcss";
export default {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: { extend: {
    colors: {
      ink: "#0a0b0d", surface: "#13161b", muted: "#1c2026", border: "#2a2e36",
      text: "#e8eaef", dim: "#8b9099",
      brand: { DEFAULT: "#f97316", soft: "#f97316cc", deep: "#f9731688" },
    },
    fontFamily: { sans: ["Inter","system-ui"], mono: ["JetBrains Mono","ui-monospace"] },
  } },
} satisfies Config;

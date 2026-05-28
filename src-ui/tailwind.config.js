/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        "qise-deep": "#f3f8fc",
        "qise-surface": "#ffffff",
        "qise-card": "#edf5fa",
        "qise-red": "#ff5f6f",
        "qise-blue": "#2878d8",
        "qise-green": "#1c9f78",
        "qise-yellow": "#d99016",
      },
      fontFamily: {
        sans: ['"Inter"', "system-ui", "sans-serif"],
        mono: ['"GeistMono"', "ui-monospace", "monospace"],
      },
    },
  },
  plugins: [],
};

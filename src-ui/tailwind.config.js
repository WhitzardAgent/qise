/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        "qise-deep": "#07080a",
        "qise-surface": "#101111",
        "qise-card": "#1b1c1e",
        "qise-red": "#FF6363",
        "qise-blue": "#55b3ff",
        "qise-green": "#5fc992",
        "qise-yellow": "#ffbc33",
      },
      fontFamily: {
        sans: ['"Inter"', "system-ui", "sans-serif"],
        mono: ['"GeistMono"', "ui-monospace", "monospace"],
      },
    },
  },
  plugins: [],
};

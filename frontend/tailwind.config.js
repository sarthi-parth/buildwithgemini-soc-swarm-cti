/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        soc: {
          bg: "#090d16",
          card: "#0f172a",
          border: "#1e293b",
          highlight: "#1e293b",
          primary: "#38bdf8",
          secondary: "#818cf8",
          accent: "#22c55e",
          danger: "#ef4444",
          warning: "#f59e0b"
        }
      }
    },
  },
  plugins: [],
}

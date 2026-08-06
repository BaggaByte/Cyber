"use client";

import { useState, useEffect } from "react";
import { Sun, Moon, Monitor } from "lucide-react";

export default function ThemeSwitcher() {
  const [theme, setTheme] = useState<"light" | "dark" | "system">("system");
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    const savedTheme = (localStorage.getItem("theme") as "light" | "dark" | "system") || "system";
    setTheme(savedTheme);
    setMounted(true);
  }, []);

  const changeTheme = (newTheme: "light" | "dark" | "system") => {
    setTheme(newTheme);
    localStorage.setItem("theme", newTheme);
    
    const isDark = newTheme === "dark" || (newTheme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
    
    if (isDark) {
      document.documentElement.classList.add('dark');
      document.documentElement.setAttribute('data-theme', 'dark');
    } else {
      document.documentElement.classList.remove('dark');
      document.documentElement.setAttribute('data-theme', 'light');
    }
    
    document.documentElement.style.colorScheme = isDark ? "dark" : "light";
  };

  if (!mounted) {
    return (
      <div className="w-9 h-9 rounded-lg bg-slate-200 dark:bg-slate-800 animate-pulse" />
    );
  }

  const cycleTheme = () => {
    if (theme === "system") changeTheme("light");
    else if (theme === "light") changeTheme("dark");
    else changeTheme("system");
  };

  const getIcon = () => {
    switch (theme) {
      case "light":
        return <Sun size={18} className="text-slate-600" />;
      case "dark":
        return <Moon size={18} className="text-slate-300" />;
      case "system":
      default:
        return <Monitor size={18} className="text-slate-500 dark:text-slate-400" />;
    }
  };

  const getLabel = () => {
    switch (theme) {
      case "light": return "Light Mode";
      case "dark": return "Dark Mode";
      case "system": return "System Theme";
    }
  };

  return (
    <button
      onClick={cycleTheme}
      title={`Current: ${getLabel()}. Click to cycle.`}
      className="flex items-center justify-center w-10 h-10 rounded-xl bg-white/50 dark:bg-slate-900/50 backdrop-blur-md border border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800/80 transition-all duration-200 shadow-sm"
    >
      {getIcon()}
    </button>
  );
}

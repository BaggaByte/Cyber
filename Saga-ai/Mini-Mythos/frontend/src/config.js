/** Shared backend URL — must match start-backend.bat / uvicorn port */
export const API_BASE = import.meta.env.VITE_API_BASE || 'http://127.0.0.1:8083';

export function wsUrl(path) {
  const wsBase = API_BASE.replace(/^http/, 'ws');
  return `${wsBase}${path}`;
}

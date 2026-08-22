import { create } from "zustand";

interface Message {
  role: "user" | "assistant";
  content: string;
}

interface ChatStore {
  isOpen: boolean;
  messages: Message[];
  context: string | null;
  toggleDrawer: () => void;
  openDrawerWithContext: (context: string) => void;
  addMessage: (msg: Message) => void;
  setMessages: (msgs: Message[]) => void;
}

export const useChatStore = create<ChatStore>((set) => ({
  isOpen: false,
  messages: [],
  context: null,
  toggleDrawer: () => set((state) => ({ isOpen: !state.isOpen })),
  openDrawerWithContext: (context) => set({ isOpen: true, context }),
  addMessage: (msg) => set((state) => ({ messages: [...state.messages, msg] })),
  setMessages: (msgs) => set({ messages: msgs }),
}));

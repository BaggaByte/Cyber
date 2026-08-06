import os

# System Configuration
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
MODEL_NAME = os.getenv("MODEL_NAME", "GPT-OSS 120B")
MAX_AGENT_CYCLES = 3
TARGET_URL = "http://testphp.vulnweb.com" # Safe, legal testing ground

DEFAULT_MODEL = MODEL_NAME
DEFAULT_API_URL = "https://api.groq.com/openai/v1"
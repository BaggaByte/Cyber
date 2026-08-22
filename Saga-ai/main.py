import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import chromadb
import ollama
import uuid
from tenacity import retry, stop_after_attempt, wait_fixed

app = FastAPI(title="Aegis AI Proxy")

# CORS: allow Next.js frontend and any local development origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize ChromaDB — ensure the storage directory exists first
CHROMA_PATH = os.environ.get("CHROMA_PATH", "/app/aegis_chroma_db")
os.makedirs(CHROMA_PATH, exist_ok=True)

@retry(stop=stop_after_attempt(5), wait=wait_fixed(2))
def init_chroma():
    return chromadb.PersistentClient(path=CHROMA_PATH)

chroma_client = init_chroma()
collection = chroma_client.get_or_create_collection(name="remediations")

# Initialize Ollama client
ollama_base_url = os.environ.get("OLLAMA_BASE_URL", "http://host.docker.internal:11434")
ollama_model = os.environ.get("OLLAMA_MODEL", "llama3.1")
ollama_client = ollama.Client(host=ollama_base_url)

class FindingRequest(BaseModel):
    vulnerability_id: str
    description: str
    target: str

@app.get("/health")
def health_check():
    return {"status": "ok", "ai_configured": True}

@app.post("/analyze/")
def analyze_finding(finding: FindingRequest):
    # 1. RAG: Search ChromaDB for similar past remediations
    query_text = f"Target: {finding.target} Vuln: {finding.vulnerability_id} Desc: {finding.description}"
    
    # Simple query
    results = collection.query(
        query_texts=[query_text],
        n_results=2
    )
    
    context = ""
    if results and results['documents'] and len(results['documents'][0]) > 0:
        context = "\nHistorical Context/Previous Remediations:\n" + "\n".join(results['documents'][0])

    # 2. Ask Ollama to generate a remediation plan
    prompt = f"""
    You are an expert cybersecurity analyst. Provide a remediation plan for the following finding.
    
    Vulnerability ID: {finding.vulnerability_id}
    Target: {finding.target}
    Description: {finding.description}
    {context}
    
    Provide actionable steps to secure this target.
    """
    
    try:
        completion = ollama_client.chat(
            model=ollama_model,
            messages=[
                {"role": "system", "content": "You are Aegis, an AI security advisor."},
                {"role": "user", "content": prompt}
            ],
            options={
                "temperature": 0.3,
                "num_predict": 1024
            }
        )
        
        remediation_plan = completion["message"]["content"]
        
        # 3. Save the new analysis into ChromaDB for future memory
        doc_id = str(uuid.uuid4())
        collection.add(
            documents=[remediation_plan],
            metadatas=[{"vulnerability_id": finding.vulnerability_id, "target": finding.target}],
            ids=[doc_id]
        )
        
        return {
            "vulnerability_id": finding.vulnerability_id,
            "remediation_plan": remediation_plan,
            "memory_id": doc_id
        }
    except ollama.ResponseError as e:
        raise HTTPException(status_code=500, detail=f"Ollama Error: {e.error}")
    except Exception as e:
        # Surface meaningful error messages, mask internal details in production
        err_msg = str(e)
        if "timeout" in err_msg.lower() or "timed out" in err_msg.lower():
            raise HTTPException(status_code=504, detail="AI service request timed out. Please retry.")
        raise HTTPException(status_code=500, detail=err_msg)

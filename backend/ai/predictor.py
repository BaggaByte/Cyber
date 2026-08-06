from pathlib import Path
import torch
from transformers import AutoModelForSeq2SeqLM, AutoTokenizer

class AttackPathPredictor:
    """Load a seq2seq model that, given a graph representation, predicts likely attack paths.
    This is a placeholder implementation – replace model_name with an actual fine‑tuned checkpoint.
    """
    def __init__(self, model_path: str = "models/attack_path_predictor/"):
        self.model_path = Path(model_path)
        # Load model & tokenizer – fall back to a small generic model if not found
        if (self.model_path / "pytorch_model.bin").exists():
            self.tokenizer = AutoTokenizer.from_pretrained(str(self.model_path))
            self.model = AutoModelForSeq2SeqLM.from_pretrained(str(self.model_path))
        else:
            # Use a tiny open‑source model as a stub
            self.tokenizer = AutoTokenizer.from_pretrained("google/flan-t5-small")
            self.model = AutoModelForSeq2SeqLM.from_pretrained("google/flan-t5-small")
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)

    def _serialize_graph(self, graph_json: dict) -> str:
        """Convert a Neo4j graph (as dict) to a prompt string for the LLM."""
        # Very simple serialization – real implementation would be richer
        return f"Graph nodes: {list(graph_json.get('nodes', []))}\nEdges: {list(graph_json.get('relationships', []))}"

    def predict(self, graph_json: dict, top_k: int = 5) -> list:
        """Return a list of the top‑k predicted attack paths.
        Each entry is a dict with ``path`` (list of node ids) and ``score``.
        """
        prompt = self._serialize_graph(graph_json) + "\nPredict the most likely attack paths (in order, JSON list)."
        inputs = self.tokenizer(prompt, return_tensors="pt", truncation=True, max_length=1024).to(self.device)
        output = self.model.generate(**inputs, max_new_tokens=256, num_return_sequences=top_k, do_sample=True, temperature=0.7)
        predictions = []
        for seq in output:
            text = self.tokenizer.decode(seq, skip_special_tokens=True)
            predictions.append(text.strip())
        return predictions

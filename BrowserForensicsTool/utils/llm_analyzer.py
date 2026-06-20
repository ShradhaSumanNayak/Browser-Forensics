import os
import datetime
from pathlib import Path
try:
    from llama_cpp import Llama
    from huggingface_hub import hf_hub_download
    IMPORT_ERROR_MSG = "Missing AI dependencies. Please run: pip install llama-cpp-python huggingface-hub"
except ImportError:
    Llama = None
    hf_hub_download = None
    IMPORT_ERROR_MSG = "Missing AI dependencies. Please run: pip install llama-cpp-python huggingface-hub"

class LLMIntentAnalyzer:
    IMPORT_ERROR_MSG = IMPORT_ERROR_MSG # Make it accessible via self
    """
    A lightweight local LLM wrapper designed to ingest chunks of browsing 
    timeline data and generate natural-language human intent summaries.
    """
    
    # We use a very small, heavily quantized instruction model so it runs on CPU 
    # without exploding RAM or taking forever.
    DEFAULT_REPO = "Qwen/Qwen1.5-1.8B-Chat-GGUF"
    DEFAULT_FILE = "qwen1_5-1_8b-chat-q4_k_m.gguf"
    
    def __init__(self, logger_callback=None, model_dir=None):
        self.logger_callback = logger_callback
        self.model_dir = model_dir or Path(os.path.expanduser("~")) / ".cache" / "browser_forensics_models"
        self.llm = None
        self.is_loaded = False
        
    def log(self, msg):
        if self.logger_callback:
            self.logger_callback(msg)
        else:
            print(msg)
            
    def download_model(self, repo_id=DEFAULT_REPO, filename=DEFAULT_FILE):
        if not hf_hub_download:
            self.log("[-] huggingface_hub is not installed. Cannot download model.")
            return False
            
        self.model_dir.mkdir(parents=True, exist_ok=True)
        expected_path = self.model_dir / filename
        
        if expected_path.exists():
            self.log(f"[*] Local LLM model found at {expected_path}")
            return str(expected_path)
            
        self.log(f"[*] Downloading Intent Reconstruction Model {filename} (This may take a while)...")
        try:
            path = hf_hub_download(
                repo_id=repo_id, 
                filename=filename, 
                cache_dir=str(self.model_dir)
            )
            self.log(f"[+] Model downloaded successfully to {path}")
            return path
        except Exception as e:
            self.log(f"[-] Failed to download model: {e}")
            return False

    def load_model(self, model_path=None):
        if not Llama:
            self.log(f"[-] llama-cpp-python is not installed. {self.IMPORT_ERROR_MSG}")
            return False
            
        if self.is_loaded:
            return True
            
        if not model_path:
            model_path = self.download_model()
            if not model_path:
                return False
                
        self.log(f"[*] Loading LLM into memory from {model_path}...")
        # Attempt multiple sensible parameter combinations and provide clearer errors
        params_list = [
            {"n_ctx": 4096, "n_threads": max(1, os.cpu_count() // 2), "n_gpu_layers": -1},
            {"n_ctx": 2048, "n_threads": max(1, os.cpu_count() // 2), "n_gpu_layers": 0},
            {"n_ctx": 1024, "n_threads": 2, "n_gpu_layers": 0},
        ]

        last_err = None
        for params in params_list:
            try:
                self.log(f"[*] Loading LLM with params: {params}")
                self.llm = Llama(model_path=model_path, verbose=False, **params)
                self.is_loaded = True
                self.log("[+] Local LLM Intent Engine initialized successfully.")
                return True
            except Exception as e:
                last_err = e
                self.log(f"[-] LLM load attempt failed ({params}): {e}")

        self.log(f"[-] Failed to load LLM after multiple attempts: {last_err}")
        return False
            
    def _chunk_timeline(self, history_records, idle_minutes_threshold=5):
        """
        Groups chronological history records into temporal chunks (sessions).
        Starts a new chunk if there's a gap of >idle_minutes_threshold between visits.
        """
        if not history_records:
            return []
            
        # Assuming records are sorted oldest to newest (or we sort them here)
        # However, our main.py history export usually sorts newest to oldest.
        # We need oldest to newest to understand progression.
        sorted_records = sorted(
            [r for r in history_records if r.get("Last Visit Time")],
            key=lambda x: str(x.get("Last Visit Time"))
        )
        
        chunks = []
        current_chunk = []
        last_time = None
        
        for record in sorted_records:
            t_val = record.get("Last Visit Time")
            if not t_val:
                continue
                
            if isinstance(t_val, datetime.datetime):
                t_obj = t_val
            else:
                try:
                    # Expected format: "2026-03-12 10:45:30"
                    t_str = str(t_val)
                    if " " in t_str and "." in t_str: # handle milliseconds
                         t_str = t_str.split(".")[0]
                    t_obj = datetime.datetime.fromisoformat(t_str)
                except ValueError:
                    continue
                
            if not last_time:
                last_time = t_obj
                current_chunk.append(record)
                continue
                
            delta = t_obj - last_time
            if delta.total_seconds() > (idle_minutes_threshold * 60):
                if current_chunk:
                    chunks.append(current_chunk)
                current_chunk = [record]
            else:
                current_chunk.append(record)
                
            last_time = t_obj
                
        if current_chunk:
            chunks.append(current_chunk)
            
        return chunks

    def construct_prompt(self, records_chunk):
        """
        Builds the strict prompt for the instruction-tuned model.
        """
        prompt = (
            "You are an expert digital forensics analyst. Read the following chronological slice of a user's web browsing "
            "history and search queries over a brief period. Write exactly a 2-sentence summary deducing the user's primary "
            "intent, goals, or activities during this session. Do not list URLs. State what they were trying to accomplish.\n\n"
            "BROWSING HISTORY:\n"
        )
        
        # Dynamically size the prompt to avoid blowing up the context window (4096 tokens).
        # We allow up to ~6000 characters of URLs which is roughly ~1500 tokens, very safe.
        max_chars = 6000 
        current_chars = 0
        
        for r in records_chunk:
            # Ensure timestamp is a string before splitting to avoid AttributeError on datetime objects
            ts_val = str(r.get("Last Visit Time", ""))
            time = ts_val.split(" ")[-1] if " " in ts_val else ts_val
            title = r.get("Title", "Unknown Title")
            url = r.get("URL", "")
            if len(url) > 80:
                url = url[:77] + "..."
            
            line = f"- [{time}] {title} ({url})\n"
            if current_chars + len(line) > max_chars:
                prompt += f"... [Truncated {len(records_chunk) - records_chunk.index(r)} remaining items due to context length]\n"
                break
                
            prompt += line
            current_chars += len(line)
            
        return prompt

    def analyze_timeline(self, history_records):
        """
        Takes raw history dicts, loads model, chunks by time, and generates intent summaries.
        Returns a list of dicts suitable for CSV export.
        """
        if not self.load_model():
            return []
            
        self.log(f"[*] Chunking {len(history_records)} history records for LLM Intent Analysis...")
        chunks = self._chunk_timeline(history_records, idle_minutes_threshold=5)
        
        results = []
        self.log(f"[*] Analyzing {len(chunks)} chronological browsing sessions...")
        
        for i, chunk in enumerate(chunks):
            if len(chunk) < 1: 
                # Ignore empty sessions
                continue
                
            start = chunk[0].get("Last Visit Time", "")
            end = chunk[-1].get("Last Visit Time", "")
            
            prompt = self.construct_prompt(chunk)
            
            try:
                # Using create_chat_completion without strict JSON grammar to prevent backend crashes, 
                # relying on system prompt and robust fallback parsing.
                response = self.llm.create_chat_completion(
                    messages=[
                        {"role": "system", "content": "You are a forensic AI. Output ONLY valid JSON in the exact format: {\"intent_summary\": \"<your 2 sentence summary here>\"}. Do not output any other text or markdown formatting."},
                        {"role": "user", "content": prompt}
                    ],
                    max_tokens=200,
                    temperature=0.2
                )
                
                # Safely extract text
                choices = response.get("choices", [])
                if not choices:
                    raise ValueError("No choices returned from LLM")
                    
                message = choices[0].get("message", {})
                output_text = message.get("content", "").strip()
                
                # Strip markdown codeblocks if the LLM added them
                if output_text.startswith("```json"):
                    output_text = output_text[7:]
                elif output_text.startswith("```"):
                    output_text = output_text[3:]
                if output_text.endswith("```"):
                    output_text = output_text[:-3]
                output_text = output_text.strip()
                
                try:
                    import json
                    parsed = json.loads(output_text)
                    final_summary = parsed.get("intent_summary", output_text)
                except json.JSONDecodeError:
                    final_summary = output_text # Fallback to raw text if JSON fails
                
                results.append({
                    "Session Start": start,
                    "Session End": end,
                    "URLs Visited": len(chunk),
                    "Reconstructed Intent": final_summary
                })
                
                if (i + 1) % 5 == 0:
                    self.log(f"    -> Analyzed {i + 1}/{len(chunks)} sessions...")
                    
            except Exception as e:
                self.log(f"[-] LLM Generation Error on chunk {i}: {e}")
                results.append({
                    "Session Start": start,
                    "Session End": end,
                    "URLs Visited": len(chunk),
                    "Reconstructed Intent": f"<Analysis Error: {str(e)}>"
                })
                
        self.log(f"[+] LLM Intent Analysis completed. Reconstructed {len(results)} session intents.")
        return results

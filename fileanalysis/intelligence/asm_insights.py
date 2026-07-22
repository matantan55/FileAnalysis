"""Local HuggingFace model for generating AI assembly insights."""

import os
import logging
import warnings
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"
warnings.filterwarnings("ignore")
logging.getLogger("transformers").setLevel(logging.ERROR)

logger = logging.getLogger(__name__)

class ASMInsightsGenerator:
    """Lazily loads a small local LLM to explain assembly code."""
    
    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.device = "cpu"
        self.model_id = "Qwen/Qwen2.5-Coder-0.5B-Instruct"

    def _load_model(self):
        if self.model is not None:
            return
            
        # Detect device
        if torch.backends.mps.is_available():
            self.device = "mps"
        elif torch.cuda.is_available():
            self.device = "cuda"
        else:
            self.device = "cpu"
            
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_id, local_files_only=True)
        self.model = AutoModelForCausalLM.from_pretrained(
            self.model_id,
            torch_dtype=torch.float16 if self.device != "cpu" else torch.float32,
            local_files_only=True
        ).to(self.device)
        # Optimize inference speed
        self.model.eval()

    def generate_insight(self, asm_code: str) -> str:
        """Generate a concise explanation for the provided assembly block."""
        self._load_model()
        
        prompt = (
            "You are an expert malware reverse engineer. "
            "Analyze the following assembly code block and provide a concise, 1-2 sentence explanation of what it does.\n\n"
            f"```assembly\n{asm_code}\n```"
        )
        
        messages = [
            {"role": "system", "content": "You are a concise and direct reverse engineering assistant. Do not use filler text."},
            {"role": "user", "content": prompt}
        ]
        
        text = self.tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True
        )
        
        model_inputs = self.tokenizer([text], return_tensors="pt").to(self.model.device)
        
        with torch.no_grad():
            generated_ids = self.model.generate(
                **model_inputs,
                max_new_tokens=150,
                temperature=0.2,
                do_sample=True,
                pad_token_id=self.tokenizer.eos_token_id
            )
        
        generated_ids = [
            output_ids[len(input_ids):] for input_ids, output_ids in zip(model_inputs.input_ids, generated_ids)
        ]
        
        response = self.tokenizer.batch_decode(generated_ids, skip_special_tokens=True)[0]
        return response.strip()

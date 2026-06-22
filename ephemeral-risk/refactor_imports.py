import os
import re

backend_modules = ["main", "auth", "config", "database", "notifier", "remediation"]
model_modules = ["ml_pipeline", "correlator", "detector", "features", "narrative", "pipeline", "telemetry_normalizer", "train_model"]

dirs_to_process = ["backend", "model", "scripts"]

replacements = []
for m in backend_modules:
    replacements.append((rf"from {m}\b", rf"from backend.{m}"))
    replacements.append((rf"import {m}\b", rf"from backend import {m}"))

for m in model_modules:
    replacements.append((rf"from {m}\b", rf"from model.{m}"))
    replacements.append((rf"import {m}\b", rf"from model import {m}"))

for d in dirs_to_process:
    for root, _, files in os.walk(d):
        for file in files:
            if file.endswith(".py"):
                path = os.path.join(root, file)
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                
                original = content
                for pat, rep in replacements:
                    content = re.sub(pat, rep, content)
                
                if content != original:
                    with open(path, "w", encoding="utf-8") as f:
                        f.write(content)
                    print(f"Updated {path}")

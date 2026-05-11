with open("backend/main.py", "r", encoding="utf-8", errors="replace") as f:
    content = f.read()

content = content.replace(
    "model_key = getattr(data, 'model', 'random_forest') or 'random_forest'",
    "model_key = (data.model if data.model else 'random_forest')"
)

with open("backend/main.py", "w", encoding="utf-8") as f:
    f.write(content)

print("Fixed:", "data.model if data.model" in content)

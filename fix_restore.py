with open("backend/main.py", "r", encoding="utf-8", errors="replace") as f:
    content = f.read()

# Restore original working line
content = content.replace(
    "model_key = (data.model if data.model else 'random_forest')",
    "model_key = getattr(data, 'model', 'random_forest') or 'random_forest'"
)

with open("backend/main.py", "w", encoding="utf-8") as f:
    f.write(content)

for i, line in enumerate(content.split("\n")):
    if "model_key =" in line and i > 140 and i < 160:
        print(f"Line {i+1}: {line}")

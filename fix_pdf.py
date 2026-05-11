with open("backend/pdf_report.py", "r", encoding="utf-8", errors="replace") as f:
    lines = f.readlines()

# Fix lines 238-239 (broken info_row call)
fixed = []
skip_next = False
for i, line in enumerate(lines):
    if skip_next:
        skip_next = False
        continue
    if '# sanitized below' in line and 'info_row' in line:
        fixed.append('    pdf.info_row("Date de generation", now.strftime("%d/%m/%Y a %H:%M:%S"))\n')
        skip_next = True
    else:
        fixed.append(line)

content = "".join(fixed)
clean = "".join(c if ord(c) < 128 else "-" for c in content)

with open("backend/pdf_report.py", "w", encoding="ascii", errors="replace") as f:
    f.write(clean)

import ast
ast.parse(clean)
print("Syntax OK")
print("Bad chars:", sum(1 for c in clean if ord(c) > 127))

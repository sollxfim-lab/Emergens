import io, sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
P = r"C:\Users\RDP\Documents\Emergens\Emergens\templates\js\script.js"
with io.open(P, encoding="utf-8") as f:
    text = f.read()

pos = text.index("AI ASSISTANT")
marker = "// \u2554"
start = text.rfind(marker, 0, pos)
print("start char:", start)
print(repr(text[start:start + 300]))


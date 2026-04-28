with open('api/main.py') as f:
    lines = f.readlines()
for i, line in enumerate(lines[25:35], start=26):
    print(i, line.rstrip())
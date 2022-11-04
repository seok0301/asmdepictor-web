import json

f = open('/home/seok/AsmDepictor/asmdepictor-web/duplicate_functions.txt', 'r')
lines = f.readlines()
f.close()

preprocess_lines = []
for line in lines:
    line = line.split(",")
    line.pop()
    preprocess_lines.append([item.strip() for item in line])
print(preprocess_lines)
f.close()

with open('/home/seok/AsmDepictor/asmdepictor-web/duplicate_functions.json', 'w') as f:
    json.dump(preprocess_lines, f)
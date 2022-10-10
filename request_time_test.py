import requests
import json
import time

temp_file_name = 1825991262

with open(f'/home/seok/AsmDepictor/asmdepictor-web/{temp_file_name}.json', 'r') as f:
    result = json.load(f)

start = time.time()
print("Predict start.")

for idx in range(len(result)):
    print(f"Predicting...\t{idx + 1} / {len(result)}", end='\r')
    requests.post("http://localhost:30303/predictions/AsmDepictor", json={'code': result[idx]['inst']})
    
print("Predict finish.")
end = time.time()

print(f"time: {end - start}")
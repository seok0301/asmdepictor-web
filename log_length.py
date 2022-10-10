import json

with open('/home/seok/AsmDepictor/asmdepictor-web/function_log.json', 'r') as f:
    function_log = json.load(f)
    
print(len(function_log))
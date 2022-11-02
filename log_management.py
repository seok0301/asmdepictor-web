import time
import json

MAX_LOG_LENGTH = 1000000

print("Log management script start.")

while True:
    with open('/home/seok/AsmDepictor/asmdepictor-web/function_log.json', 'r') as f:
        function_log = json.load(f)
    
    print(f"Log length: {len(function_log)}")
    
    if len(function_log) > MAX_LOG_LENGTH:
        before = len(function_log)
        function_log = {key: value for key, value in function_log.items() if value['cnt'] != 1}
        after = len(function_log)
        with open('/home/seok/AsmDepictor/asmdepictor-web/function_log.json', 'w') as f:
            json.dump(function_log, f)
        print(f"Log files cleaned. {before} -> {after}")
        
    time.sleep(1800)
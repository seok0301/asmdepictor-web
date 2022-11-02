import requests
import sys
import json

with open('/home/seok/AsmDepictor/asmdepictor-web/function_log.json', 'r') as f:
    function_log = json.load(f)
    
temp_file_name = sys.argv[1]

print("Predict start.")
with open('/home/seok/AsmDepictor/asmdepictor-web/' + temp_file_name + '.json', 'r') as f:
    result = json.load(f)

for idx in range(len(result)):
    print(f"Predicting...\t{idx + 1} / {len(result)}", end='\r')
    
    # 300자 이상 함수 자르고 long True 선언
    result[idx]['long'] = False
    split_inst = result[idx]["inst"].split(" ")
    if len(split_inst) > 300:
        result[idx]['long'] = True
        split_inst = split_inst[:300]
        result[idx]["inst"] = " ".join(split_inst)
        
    if result[idx]['inst'] in function_log:
        result[idx]['func'] = function_log[result[idx]['inst']]['func']
        function_log[result[idx]['inst']]['cnt'] += 1
    else:
        predict_sentence = requests.post("http://localhost:30303/predictions/AsmDepictor", json={'code': result[idx]['inst']}).text
        print(predict_sentence)
        result[idx]['func'] = predict_sentence
        function_log[result[idx]['inst']] = {"func": predict_sentence, "cnt": 1}
        
with open('/home/seok/AsmDepictor/asmdepictor-web/' + temp_file_name + ".json", 'w') as f:
    json.dump(result, f)
with open('/home/seok/AsmDepictor/asmdepictor-web/function_log.json', 'w') as f:
    json.dump(function_log, f)

print("Predict finish.")
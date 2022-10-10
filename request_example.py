import requests
    
while True:
    try:
        requests.post("http://localhost:8081/ping")
    except:
        print("Failed to connect model server.")
        break

    code = input("Input Code:\n")
    response = requests.post("http://localhost:8081/predictions/AsmDepictor", json={'code': code})
    print("Output Text:")
    print(response.text)
    print()

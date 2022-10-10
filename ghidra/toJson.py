from contextlib import closing
import shelve
import json

with closing(shelve.open('db')) as db:
    py_dict= dict(db)
    with open('result_ghidra.json', 'w') as f:
        f.write(json.dumps(py_dict))
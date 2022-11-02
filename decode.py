from capstone import *
import subprocess
import json
import sys

def db_analysis(json_data):
    total_data = []
    result_tmp = dict()

    for count in range(len(json_data)):

        ref_string = []
        inst = json_data[count].get('inst', [])
        
        if inst:
            byte_inst = json_data[count]['inst'].split(',')
            if len(json_data[count]['xref']) > 0:
                for num in range(len(json_data[count]['xref'])):
                    ref_string.append(json_data[count]['xref'][num]['from'])

            byte_list = []

            for j in byte_inst:
                try:
                    if j.startswith('use') != True:
                        byte = b""
                        byte += bytearray.fromhex(j)
                        byte_list.append(byte)
                    else:
                        byte_list.append(j)

                except:
                    byte_list.append('Error')

            tmp_dict = {'byte_code': byte_list,
                        'start_addr': json_data[count]['addr'], 'end_addr': json_data[count]['ret'], 'ref_string': ref_string}
            result_tmp = {
                'func_name': json_data[count]['name'], 'data': tmp_dict}
            total_data.append(result_tmp)
    # asm / func name / number of BB / number of inst / start addr
    return total_data

file_path = sys.argv[1]
file_name = sys.argv[2]

with open (file_path, "r") as f:
    data = json.load(f)
md = Cs(CS_ARCH_X86, CS_MODE_64)

encode_data = db_analysis(data[file_name])
encode_txt = []

for func in encode_data:
    if "data" not in func: continue
    normalized_instrucntions = ''
    CODE = func["data"]["byte_code"]
    for inst in CODE:
        for j in md.disasm(inst, 0):
            opcode = j.mnemonic
            
            #passing nop
            if opcode == 'nop':
                continue
            try:
                operands_str = j.op_str
                operands = [x.strip() for x in operands_str.strip().split(',')]
                normalized_instr = opcode if len(operands_str) == 0 \
                        else str(opcode + '_' + '_'.join(operands))
                normalized_instrucntions += normalized_instr + ', '
            except AttributeError:
                print("Error is created on operands parts")
                pass
        
    normalized_instrucntions = normalized_instrucntions.replace(' + ', '+').replace(' - ', '-').replace(' ', '_').replace(',_', ', ')[:-2]
    encode_txt.append(normalized_instrucntions + "\n")

with open(file_path[:-5] + ".txt", 'w') as outfile:
    outfile.writelines(encode_txt)
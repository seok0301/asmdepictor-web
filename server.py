from flask import Flask, request
from torchtext.data import Field, TabularDataset
from model.asmdepictor.Translator import Translator
import model.asmdepictor.Models as Asmdepictor
import torch.nn as nn
import torch
import os
import json

app = Flask(__name__)

@app.route('/', methods = ['GET'])
def predict():
    print("Predict start.")
    temp_file_name = request.args.get('temp_file_name')
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
            result[idx]['func'] = function_log[result[idx]['inst']]
        else:
            sentence = tokenize(result[idx]['inst'])
            unk_idx = code.vocab.stoi[code.unk_token]
            pad_idx = code.vocab.stoi[code.pad_token]
            sentence_idx = [code.vocab.stoi.get(i, unk_idx) for i in sentence]

            for i in range(max_token_seq_len-len(sentence_idx)):
                sentence_idx.append(code.vocab.stoi.get(i, pad_idx))

            sentence_tensor = torch.tensor(sentence_idx).to(device)
            input_tensor = sentence_tensor.unsqueeze(0)

            translator = Translator(
                    model=model,
                    beam_size=5,
                    max_seq_len=max_token_seq_len+3,
                    src_pad_idx=code.vocab.stoi['<pad>'],
                    trg_pad_idx=text.vocab.stoi['<pad>'],
                    trg_bos_idx=text.vocab.stoi['<sos>'],
                    trg_eos_idx=text.vocab.stoi['<eos>']).to(device)

            output_tensor = translator.translate_sentence(input_tensor)
            predict_sentence = ' '.join(text.vocab.itos[idx] for idx in output_tensor)
            predict_sentence = predict_sentence.replace('<sos>', '').replace('<eos>', '').strip()

            result[idx]['func'] = predict_sentence
            function_log[result[idx]['inst']] = predict_sentence
            
    with open('/home/seok/AsmDepictor/asmdepictor-web/' + temp_file_name + ".json", 'w') as f:
        json.dump(result, f)
    
    print("Predict finish.")
    with open('/home/seok/AsmDepictor/asmdepictor-web/function_log.json', 'r') as f:
        json.dump(function_log, f)
    return "OK"


if __name__ == '__main__':
    os.environ["CUDA_VISIBLE_DEVICES"]="0"

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    max_token_seq_len = 300

    train_json_dir = './dataset/train.json'
    test_json_dir = './dataset/test.json'
    model_path = './dataset/asmdepictor_pretrained.param'

    global tokenize
    tokenize = lambda x : x.split()

    code = Field(sequential=True, 
                use_vocab=True, 
                tokenize=tokenize, 
                lower=True,
                pad_token='<pad>',
                fix_length=max_token_seq_len)

    text = Field(sequential=True, 
                use_vocab=True, 
                tokenize=tokenize, 
                lower=True,
                init_token='<sos>',
                eos_token='<eos>',
                pad_token='<pad>',
                fix_length=max_token_seq_len)

    fields = {'Code' : ('code', code), 'Text' : ('text', text)}

    train_data, test_data = TabularDataset.splits(path='',
                                                train=train_json_dir,
                                                test=test_json_dir,
                                                format='json',
                                                fields=fields)

    # share train & tgt word2idx
    code.build_vocab(train_data.code, train_data.text, min_freq=2)
    text.build_vocab(train_data.code, train_data.text, min_freq=0)

    # model
    d_inner_hid=2048
    d_k=64 
    d_model=512 
    d_v=64
    d_word_vec=512
    dropout=0.1
    embs_share_weight=True
    n_head=8 
    n_layers=3 
    proj_share_weight=True
    scale_emb_or_prj='emb'

    src_pad_idx=code.vocab.stoi['<pad>']
    src_vocab_size=len(code.vocab.stoi)
    trg_pad_idx=text.vocab.stoi['<pad>']
    trg_vocab_size=len(text.vocab.stoi)

    model = Asmdepictor.Asmdepictor(src_vocab_size,
                                    trg_vocab_size,
                                    src_pad_idx=src_pad_idx,
                                    trg_pad_idx=trg_pad_idx,
                                    trg_emb_prj_weight_sharing=proj_share_weight,
                                    emb_src_trg_weight_sharing=embs_share_weight,
                                    d_k=d_k,
                                    d_v=d_v,
                                    d_model=d_model,
                                    d_word_vec=d_word_vec,
                                    d_inner=d_inner_hid,
                                    n_layers=n_layers,
                                    n_head=n_head,
                                    dropout=dropout,
                                    scale_emb_or_prj=scale_emb_or_prj,
                                    n_position=max_token_seq_len+3).to(device)

    model = nn.DataParallel(model)
    state_dict = torch.load(model_path)

    model.load_state_dict(torch.load(model_path))
    model.to(device)

    print("Model succesfuly loaded.")

    with open('/home/seok/AsmDepictor/asmdepictor-web/function_log.json', 'r') as f:
        function_log = json.load(f)
        
    print("Log file succesfuly loaded.")
    
    app.run(host='localhost', port=8090)
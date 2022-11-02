const multer = require('multer');
const express = require('express');
const moment = require('moment');
const cors = require('cors');
const fs = require('fs');
const PORT = 8088;
const app = express();
const TIMEOUT = 60
app.use(cors());
app.use(express.json({
    limit: "50mb"
}));
app.use(express.urlencoded({
    limit: "50mb",
    extended: false
}));


//서버 따로 유지보수 시에 자동으로 설정 가능한 환경 변수들 가능한 파일
const GHIDRA_PATH = "/home/seok/ghidra_10.1.5_PUBLIC"
const ASMDEPICTOR_PATH = "/home/seok/AsmDepictor"
const example_list = ["", "diff", "dselect", "ex20_strip", "g-ir-compiler", "lsipc", "lsipc_strip", "ltrace", "lvmlockd", "pf_strip"];

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, './uploads');
    },
    filename: function (req, file, cb) {
        cb(null, moment().format('YYYYMMDDHHmmss') + '_' + file.originalname);
    }
});

const upload = multer({ storage: storage });
let time;

app.post('/upload', upload.single('file'), (req, res) => {
    time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
    console.log(time + "File upload request arrived.");
    const { fieldname, originalname, encoding, mimetype, destination, filename, path, size } = req.file
    // console.log("after exec");
    // console.log("폼에 정의된 필드명 : ", fieldname);
    // console.log("사용자가 업로드한 파일 명 : ", originalname);
    // console.log("파일의 엔코딩 타입 : ", encoding);
    // console.log("파일의 Mime 타입 : ", mimetype);
    // console.log("파일이 저장된 폴더 : ", destination);
    // console.log("destinatin에 저장된 파일 명 : ", filename);
    // console.log("업로드된 파일의 전체 경로 ", path);
    // console.log("파일의 바이트(byte 사이즈)", size);

    // file format 검사.
    const { execSync } = require("child_process");
    const fileResult = execSync(`file ${path}`,).toString().slice(0, -1);
    time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
    console.log(time + "File information:" + fileResult);
    if (!fileResult.includes("ELF") || !fileResult.includes("64-bit") || !fileResult.includes("x86-64")) {
        console.log("Binary file format is not correct.");
        res.status(200).send({ "status": 1 });
        fs.unlink(path, function (err) {
            if (err) {
                time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
                console.log(time + "Error : ", err)
            }
        })
        return;
    }

    // ghidra output을 output_inst/filename.json에 저장.
    time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
    console.log(time + "Ghidra script start.");
    const execResult = execSync(`python run.py ${GHIDRA_PATH}/support/analyzeHeadless ${ASMDEPICTOR_PATH}/asmdepictor-web/uploads/${filename} 1`,).toString().slice(0, -1);
    console.log(execResult);
    time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
    console.log(time + "Ghidra script end.");

    /////////// false말고 숫자로 넣어서 분석 실패인지 시간 초과인지 구분해서 return.
    const exists = fs.existsSync(`${ASMDEPICTOR_PATH}/asmdepictor-web/output_inst/${filename}.json`);
    if (!exists) {
        time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
        console.log(time + "Result json file not exists.");
        fs.unlink(path, function (err) {
            if (err) {
                time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
                console.log(time + "Error : ", err)
            }
        })
        res.status(200).send({ "status": 2 });
    }
    else {
        time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
        console.log(time + "Result json file exists.");

        // ghidra output json에서 inst를 incode, bytecode inst가 담긴 filename.txt 파일 생성.
        time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
        console.log(time + "Ghidra output preprocessing start.");
        execSync(`python ./decode.py ./output_inst/${filename}.json ${filename}`).toString();
        let ghidraResult = require(`${ASMDEPICTOR_PATH}/asmdepictor-web/output_inst/${filename}.json`);

        // ghidra output json에서 inst가 없는 항목 삭제.
        ghidraResult = ghidraResult[filename].filter(item => item.inst)

        // bpe과정 저친 파일 filename_bpe.txt에 저장.
        execSync(`subword-nmt apply-bpe --codes ./pretrained_voca.voc --input ./output_inst/${filename}.txt --output ./output_inst/${filename}_bpe.txt`);
        const bpe_array = fs.readFileSync(`./output_inst/${filename}_bpe.txt`).toString().split("\n");
        bpe_array.pop();

        //ghidra result에 bpe된 inst 저장.
        ghidraResult.forEach((item, idx) => ghidraResult[idx].inst = bpe_array[idx]);

        // 중복된 inst 제거.
        let duplicateIndex = [];
        let duplicateValue = [];
        let flag = true;
        for (let i = 0; i < bpe_array.length; i++) {
            flag = true;
            for (value in duplicateValue) {
                if (duplicateValue[value] === bpe_array[i]) {
                    flag = false;
                }
            }
            if (flag) {
                duplicateIndex.push(i);
                duplicateValue.push(bpe_array[i]);
            }
        }
        ghidraResult = ghidraResult.filter((item, idx) => duplicateIndex.includes(idx));
        time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
        console.log(time + "Ghidra output preprocessing end.");

        // user가 upload한 파일 삭제.
        fs.unlink("./output_inst/" + filename + ".json", function (err) {
            if (err) {
                time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
                console.log(time + "Error : ", err)
            }
        })
        fs.unlink("./output_inst/" + filename + ".txt", function (err) {
            if (err) {
                time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
                console.log(time + "Error : ", err)
            }
        })
        fs.unlink("./output_inst/" + filename + "_bpe.txt", function (err) {
            if (err) {
                time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
                console.log(time + "Error : ", err)
            }
        })
        fs.unlink("./output_section/" + filename + ".json", function (err) {
            if (err) {
                time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
                console.log(time + "Error : ", err)
            }
        })
        fs.unlink("./output_xref/" + filename + ".json", function (err) {
            if (err) {
                time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
                console.log(time + "Error : ", err)
            }
        })
        fs.unlink("./uploads/" + filename, function (err) {
            if (err) {
                time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
                console.log(time + "Error : ", err)
            }
        })
        time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
        console.log(time + "Temp file cleaned.");

        res.json(ghidraResult);
    }
});


app.post('/example', (req, res) => {
    // example binary file 도착.
    let time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
    console.log(time + "Example request arrived.");
    const idx = req.body.idx;
    const filename = example_list[idx];
    time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
    console.log(time + "Filename: " + filename);

    // ghidra output을 output_inst/filename.json에 저장.
    // const { execSync } = require("child_process");
    // const execResult = execSync(`python run.py ${GHIDRA_PATH}/support/analyzeHeadless ${ASMDEPICTOR_PATH}/asmdepictor-web/ex_binary_files/${filename} 1`,).toString();
    // console.log(execResult);

    /////////// false말고 숫자로 넣어서 분석 실패인지 시간 초과인지 구분해서 return.
    const exists = fs.existsSync(`${ASMDEPICTOR_PATH}/asmdepictor-web/output_inst/${filename}.json`);
    if (!exists) {
        time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
        console.log(time + "Result json file not exists.");
        res.status(200).send(false);
    }
    else {
        time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
        console.log(time + "Result json file exists.");

        // ghidra output json에서 inst를 incode, bytecode inst가 담긴 filename.txt 파일 생성.
        time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
        console.log(time + "Ghidra output preprocessing start.");
        // execSync(`python ./decode.py ./output_inst/${filename}.json ${filename}`).toString();
        let ghidraResult = require(`${ASMDEPICTOR_PATH}/asmdepictor-web/output_inst/${filename}.json`);

        // ghidra output json에서 inst가 없는 항목 삭제.
        ghidraResult = ghidraResult[filename].filter(item => item.inst)

        // bpe과정 저친 파일 filename_bpe.txt에 저장.
        // execSync(`subword-nmt apply-bpe --codes ./pretrained_voca.voc --input ./output_inst/${filename}.txt --output ./output_inst/${filename}_bpe.txt`);
        const bpe_array = fs.readFileSync(`./output_inst/${filename}_bpe.txt`).toString().split("\n");
        bpe_array.pop();

        //ghidra result에 bpe된 inst 저장.
        ghidraResult.forEach((item, idx) => ghidraResult[idx].inst = bpe_array[idx]);

        // 중복된 inst 제거.
        let duplicateIndex = [];
        let duplicateValue = [];
        let flag = true;
        for (let i = 0; i < bpe_array.length; i++) {
            flag = true;
            for (value in duplicateValue) {
                if (duplicateValue[value] === bpe_array[i]) {
                    flag = false;
                }
            }
            if (flag) {
                duplicateIndex.push(i);
                duplicateValue.push(bpe_array[i]);
            }
        }
        ghidraResult = ghidraResult.filter((item, idx) => duplicateIndex.includes(idx));
        time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
        console.log(time + "Ghidra output preprocessing end.");

        res.json(ghidraResult);
    }
});


app.post('/predict1', (req, res) => {
    // example binary file 도착.
    let time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
    console.log(time + "Predict request arrived.");
    let result = req.body;

    const temp_file_name = parseInt(require('crypto').randomBytes(4).toString('hex'), 16).toString();

    fs.writeFileSync(`${temp_file_name}.json`, JSON.stringify(result), function (err) {
        if (err) {
            time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
            console.log(time + err);
        }
    });

    const { execSync } = require("child_process");
    const execResult = execSync(`python ${ASMDEPICTOR_PATH}/asmdepictor-web/request.py ${temp_file_name}`);

    result = fs.readFileSync(`${ASMDEPICTOR_PATH}/asmdepictor-web/${temp_file_name}.json`);
    fs.unlink(`${ASMDEPICTOR_PATH}/asmdepictor-web/${temp_file_name}.json`, function (err) {
        if (err) {
            time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
            console.log(time + "Error : ", err)
        }
    })
    time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
    console.log(time + "Predict finish.");

    res.json(JSON.parse(result));
});


app.post('/predict2', (req, res) => {
    // example binary file 도착.
    let time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
    console.log(time + "Predict request arrived.");
    let result = req.body;

    const temp_file_name = parseInt(require('crypto').randomBytes(4).toString('hex'), 16).toString();

    fs.writeFileSync(`${temp_file_name}.json`, JSON.stringify(result), function (err) {
        if (err) {
            time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
            console.log(time + err);
        }
    });

    const { execSync } = require("child_process");
    const execResult = execSync(`python ${ASMDEPICTOR_PATH}/asmdepictor-web/request.py ${temp_file_name}`);

    result = fs.readFileSync(`${ASMDEPICTOR_PATH}/asmdepictor-web/${temp_file_name}.json`);
    fs.unlink(`${ASMDEPICTOR_PATH}/asmdepictor-web/${temp_file_name}.json`, function (err) {
        if (err) {
            time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
            console.log(time + "Error : ", err)
        }
    })
    time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
    console.log(time + "Predict finish.");

    res.json(JSON.parse(result));
});


app.post('/predict3', (req, res) => {
    // example binary file 도착.
    let time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
    console.log(time + "Predict request arrived.");
    let result = req.body;

    const temp_file_name = parseInt(require('crypto').randomBytes(4).toString('hex'), 16).toString();

    fs.writeFileSync(`${temp_file_name}.json`, JSON.stringify(result), function (err) {
        if (err) {
            time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
            console.log(time + err);
        }
    });

    const { execSync } = require("child_process");
    const execResult = execSync(`python ${ASMDEPICTOR_PATH}/asmdepictor-web/request.py ${temp_file_name}`);

    result = fs.readFileSync(`${ASMDEPICTOR_PATH}/asmdepictor-web/${temp_file_name}.json`);
    fs.unlink(`${ASMDEPICTOR_PATH}/asmdepictor-web/${temp_file_name}.json`, function (err) {
        if (err) {
            time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
            console.log(time + "Error : ", err)
        }
    })
    time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
    console.log(time + "Predict finish.");

    res.json(JSON.parse(result));
});


app.post('/stripped', upload.single('file'), (req, res) => {
    let time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
    console.log(time + "File upload request arrived to determine whether stripped or not.");
    const { fieldname, originalname, encoding, mimetype, destination, filename, path, size } = req.file
    // console.log("after exec");
    // console.log("폼에 정의된 필드명 : ", fieldname);
    // console.log("사용자가 업로드한 파일 명 : ", originalname);
    // console.log("파일의 엔코딩 타입 : ", encoding);
    // console.log("파일의 Mime 타입 : ", mimetype);
    // console.log("파일이 저장된 폴더 : ", destination);
    // console.log("destinatin에 저장된 파일 명 : ", filename);
    // console.log("업로드된 파일의 전체 경로 ", path);
    // console.log("파일의 바이트(byte 사이즈)", size);

    // file format 검사.
    const { execSync } = require("child_process");
    try {
        const fileResult = execSync(`readelf ${path} -S | grep debug`,).toString();
        time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
        console.log(time + "Not stripped binary file.");
        res.status(200).send({ "status": 0 });
        fs.unlink(path, function (err) {
            if (err) {
                time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
                console.log(time + "Error : ", err)
            }
        })
        return;
    } catch {
        time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
        console.log(time + "Stripped binary file.");
        res.status(200).send({ "status": 1 });
        fs.unlink(path, function (err) {
            if (err) {
                time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
                console.log(time + "Error : ", err)
            }
        })
        return;
    }
});


app.listen(PORT, () => {
    const time = '[' + new Date(+new Date() + 3240 * 10000).toISOString().replace('T', ' ').replace('Z', '') + '] ';
    console.log(time + "Server started.");
});
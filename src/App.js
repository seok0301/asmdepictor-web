import axios from "axios";
import React, {useState, useRef} from "react";
import styles from './styles.module.css'

const PORT = 8088
const IP = "115.145.172.80"
const TIMEOUT = 60

const example_list = ["", "diff", "dselect", "ex20_strip", "g-ir-compiler", "lsipc", "lsipc_strip", "ltrace", "lvmlockd", "pf_strip"];
const model_list = ["", "AsmDepictor1", "AsmDepictor2", "AsmDepictor3"];
let exampleFileIndex;

function App() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [selectExampleFile, setselectExampleFile] = useState(0);
  const [selectedFileName, setSelectedFileName] = useState("No file chosen");
  const [selectedFileNameForNoRendering, setselectedFileNameForNoRendering] = useState("");
  const [selectModel, setselectModel] = useState(0);
  const [binaryAnalysisResult, setBinaryAnalysisResult] = useState([]);
  const [sec, setSec] = useState(1);
  const secIntervalId = useRef(null);
  const secTimeoutId = useRef(null);
  const [isLoading, setIsLoading] = useState(false);
  const [correct, setCorrect] = useState(0);
  const [correctList, setCorrectList] = useState([]);
  const [functionNumber, setFunctionNumber] = useState(0);
  const [loadingFinish, setLoadingFinish] = useState(false);
  const [analysisFinish, setAnalysisFinish] = useState(false);
  const [predictionFinish, setPredictionFinish] = useState(false);
  const [isStripped, setisStripped] = useState(false);
  const [isToggled, setIsToggled] = useState([]);

  const toggleInstruction = (idx) => {
    let netIsToggled = [...isToggled];
    netIsToggled[idx] = !netIsToggled[idx];
    setIsToggled(netIsToggled);
  }

  //파일 업로드했을 때, selectedFile에 파일 저장
  const onFileChange = (event) => {
    setSelectedFile(event.target.files[0]);
    setSelectedFileName(event.target.files[0].name);
  }

  // select에서 binary file을 선택했을 경우 해당 정보 저장
  const SelectBinaryFile = (event) => {
    setselectExampleFile(event.target.value[0]);
  }

  // select에서 model을 선택했을 경우 해당 정보 저장
  const SelectModel = (event) => {
    setselectModel(event.target.value[0]);
  }

  const onFileDelete = () => {
    if (isLoading) return;
    setSelectedFile(null);
    setSelectedFileName("No file chosen");
  }

  const onSelectedFileDelete = () => {
    if (isLoading) return;
    setselectExampleFile(0);
  }
  
  // analysis button 클릭하여 제대로 file이 들어왔을 경우 실행되는 함수.
  // return값은 response.data, ghidra output json.
  const onFileUpload = async() => {
    // 만약 selected된 binary file일 경우, ghidra output을 response에 저장.
    ////////////// response에서 시간 넘어간 경우, fail한 경우 처리해주어야함.
    if (parseInt(selectExampleFile)) {
      const data = {idx: selectExampleFile};
      let response = undefined;
      try {
        response = await axios.post(`http://${IP}:${PORT}/example`, data);
      } catch {
        alert("Failed to receive response from server.");
        return false;
      }
      if (!response.data) {
        console.log("onFileUpload: decompile failed in gihdra.");
        alert("Decompile failed in gihdra.")
        return false;
      } else {
        console.log("onFileUpload: file upload success");
        setAnalysisFinish(true);
        return response.data;
      }
    }
  
    const formData = new FormData();
    formData.append(
      "file",
      selectedFile
    )
  
    // 만약 select아니면 form에서 데이터 가져와서 post.
    ////////////// response에서 시간 넘어간 경우, fail한 경우 처리해주어야함.

    let response = undefined;
    try {
      response = await axios.post(`http://${IP}:${PORT}/upload`, formData);
    } catch {
      alert("Failed to receive response from server.");
      window.location.reload();
    }
  
    if (response.data["status"] === 1) {
      console.log("Please upload a file that meets the conditions.");
      alert("File formet must be ELF, 64-bit, x86-64.")
      return false;
    } else if (response.data["status"] === 2) {
      console.log("onFileUpload: decompile failed in gihdra.");
      alert("Decompile failed in gihdra.")
      return false;
    } else {
      console.log("onFileUpload: file upload success");
      setAnalysisFinish(true);
      return response.data;
    }
  }

  // analysis button을 클릭했을 때 실행되는 함수.
  const AnalysisButtonClick = async () => {
    if (isLoading) return;
    setBinaryAnalysisResult([]);
    setAnalysisFinish(false);
    setPredictionFinish(false);
    // 파일을 선택하지 않았을 경우, 파일 크기가 2mb가 넘을 경우, 두 경로에서 파일을 택했을 경우 리턴.
    // 성공적으로 로딩했으므로 isLoading true, showTimer true.
    console.log("Analysis button clicked");
    if (!selectedFile && !parseInt(selectExampleFile)) {
      alert("Please select binary file.");
      setIsLoading(false);
      setLoadingFinish(false);
      return;
    } else if (selectedFile && parseInt(selectExampleFile)) {
      alert("Please select only one local file or example file.");
      setIsLoading(false);
      setLoadingFinish(false);
      return;
    } else if (selectedFile && selectedFile.size >= 2097152) {
      alert("Binary file size cannot exceed 2mb.");
      setIsLoading(false);
      setLoadingFinish(false);
      return;
    }
    if (!parseInt(selectModel)) {
      alert("Please select the model.");
      setIsLoading(false);
      setLoadingFinish(false);
      return;
    }

    console.log("selectedFile: ");
    console.log(selectedFile);
    console.log("setselectExampleFile: ");
    console.log(selectExampleFile);

    setIsLoading(true);
    setLoadingFinish(false);
    exampleFileIndex = selectExampleFile;
    setSec(1);

    if (!selectedFile) {
      setselectedFileNameForNoRendering(example_list[exampleFileIndex]);
    } else {
      setselectedFileNameForNoRendering(selectedFileName);
    }

    // 타이머 실행.
    secIntervalId.current = setInterval(() => {
      setSec(current => (current + 1));
    }, 1000);

    secTimeoutId.current = setTimeout(() => {
      alert(`File analysis exceeded ${TIMEOUT} seconds. Please select another file.`);
      window.location.reload();
    }, TIMEOUT * 1000);

    // onFileUpload함수의 결과인 ghidra output data를 result에 저장.
    let result = await onFileUpload();

    // stripped binary인지 아닌지 판단.
    let strippedFunctionCount = 0;
    for (let idx in result) {
      if (result[idx].name.substring(0, 4) === "FUN_") {
        strippedFunctionCount += 1;
      }
    }
    setisStripped(false);
    if (strippedFunctionCount * 10 > result.length) setisStripped(true);

    let newIsToggled = [];
    // toggle을 위한 배열 초기화.
    for (let idx in result) {
      newIsToggled.push(false);
    }
    setIsToggled(newIsToggled);

    // result가 없는 경우는 잘못된 경우, 함수 바로 return.
    if (!result) {
      clearInterval(secIntervalId.current);
      clearInterval(secTimeoutId.current);
      setIsLoading(false);
      setLoadingFinish(false);
      return;
    }

    // 백엔드에서 함수 이름 예측 후 반환.
    try {
      if (parseInt(selectModel) === 1) {
        result = await axios.post(`http://${IP}:${PORT}/predict1`, result);
      }
      else if (parseInt(selectModel) === 2) {
        result = await axios.post(`http://${IP}:${PORT}/predict2`, result);
      }
      else if (parseInt(selectModel) === 3) {
        result = await axios.post(`http://${IP}:${PORT}/predict3`, result);
      }
    } catch {
      alert("Failed to receive response from server.");
      window.location.reload();
    }
    result = result.data;
    setPredictionFinish(true);

    // 함수 크기 계산
    result.forEach(async (item, idx) => {
        const size = parseInt(item.ret, 16) - parseInt(item.addr - 16);
        result[idx].size = String(size) + "bytes";
    });

    // 함수 명령어 개수 계산
    result.forEach(async (item, idx) => {
        const num = item.inst.split(',').length;
        result[idx].num = num;
    });

    // binaryAnalysisResult에 ghidra output data 저장.
    setBinaryAnalysisResult(result);

    let newCorrectList = [];
    // correct rendering을 위한 배열 초기화.
    for (let idx in result) {
      newCorrectList.push(false);
    }
    setCorrectList(newCorrectList);

    // correct 개수 세기
    let correctCount = 0;
    result.forEach(async (item, idx) => {
      const split_list = item.func.split(" ");
      let flag = true;
      split_list.forEach(item => {
        if (!result[idx].name.includes(item)) {
          flag = false;
          return false;
        }
      })
      if (flag) {
        newCorrectList[idx] = true;
        correctCount += 1;
      }
    });
    setCorrect(correctCount);
    setCorrectList(newCorrectList);
    setFunctionNumber(result.length);

    // 끝났으면 timer종료.
    console.log(result);
    clearInterval(secIntervalId.current);
    clearInterval(secTimeoutId.current);
    setIsLoading(false);
    setLoadingFinish(true);
  }

  // 결과 네모 하나 하나 렌더링하는 함수
  const Result = ({idx, item}) => {
    return (
      <div key={idx} >
        <br></br>
        <div className={styles.box}>
          <table>
            <tbody>
              <tr>
                <td className={styles.text}>Model Prediction:</td>
                <td className={styles.text} style={{width:"400px"}}><b>&ensp;{item.func}</b></td>
                <td className={styles.text}>&ensp;{correctList[idx] ? <b className="correct" style={{color:"green"}}>Correct</b> : <b className="wrong" style={{color:"red"}}>Wrong</b>}</td>
              </tr>
              <tr>
                <td className={styles.text}>Function Name:</td>
                <td className={styles.text}><b>&ensp;{item.name}</b></td>
              </tr>
              <tr>
                <td className={styles.text}>Function start address:</td>
                <td className={styles.text}><b>&ensp;{item.addr}</b></td>
              </tr>
              <tr>
                <td className={styles.text}>Function end address:</td>
                <td className={styles.text}><b>&ensp;{item.ret}</b></td>
              </tr>
              <tr>
                <td className={styles.text}>Function size:</td>
                <td className={styles.text}><b>&ensp;{item.size}</b></td>
              </tr>
              <tr>
                <td className={styles.text}>Number of instructions:</td>
                <td className={styles.text}><b>&ensp;{item.num}</b></td>
              </tr>
              <tr>
                <td className={styles.text}>Instructions:</td>
                <td className={styles.text}>
                  <button className={styles.toggle_button} onClick={() => toggleInstruction(idx)}>{isToggled[idx] ? "-" : "+"}</button>
                  {item.long ? <span className={styles.inst_too_long}>* Instruction is too long, so it is truncated and used for prediction.</span> : ""}
                </td>
              </tr>
            </tbody>
          </table>
            {isToggled[idx] && <textarea className={styles.codebox} value={item.inst} disabled rows="10"></textarea>}
        </div>
      </div>
    );
  }

  // 결과 네모 하나 하나 렌더링하는 함수
  const StrippedResult = ({idx, item}) => {
    return (
      <div key={idx} >
        <br></br>
        <div className={styles.box}>
          <table>
            <tbody>
              <tr>
                <td className={styles.text}>Model Prediction:</td>
                <td className={styles.text}><b>&ensp;{item.func}</b></td>
              </tr>
              <tr>
                <td className={styles.text}>Function start address:</td>
                <td className={styles.text}><b>&ensp;{item.addr}</b></td>
              </tr>
              <tr>
                <td className={styles.text}>Function end address:</td>
                <td className={styles.text}><b>&ensp;{item.ret}</b></td>
              </tr>
              <tr>
                <td className={styles.text}>Function size:</td>
                <td className={styles.text}><b>&ensp;{item.size}</b></td>
              </tr>
              <tr>
                <td className={styles.text}>Number of instructions:</td>
                <td className={styles.text}><b>&ensp;{item.num}</b></td>
              </tr>
              <tr>
                <td className={styles.text}>Instructions:</td>
                <td className={styles.text}>
                  <button className={styles.toggle_button} onClick={() => toggleInstruction(idx)}>{isToggled[idx] ? "-" : "+"}</button>
                  {item.long ? <span className={styles.inst_too_long}>* Instruction is too long, so it is truncated and used for prediction.</span> : ""}
                </td>
              </tr>
            </tbody>
          </table>
            {isToggled[idx] && <textarea className={styles.codebox} value={item.inst} disabled rows="10"></textarea>}
        </div>
      </div>
    );
  }

  const Accuracy = () => {
    let accuracy = (correct / functionNumber) * 100;
    accuracy = accuracy.toFixed(2);
    return (
      <div>
        <h4>Model Accuracy: {accuracy}% &#40;{correct}/{functionNumber}&#41;</h4>
      </div>
    );
  }

  // 결과 렌더링
  // 파일이 선택되었거나, select에서 example binary file이 선택되었을 경우에 binaryAnalysisResult 정보 렌더링
  const ShowResult = () => {
    if (loadingFinish) {
      return (
        <div> 
          <h2>Analysis Results</h2>
          <h3>{binaryAnalysisResult.length} Functions.</h3>
          <Accuracy/>
          {binaryAnalysisResult.map((item, idx) => (
            <Result key={idx} idx={idx} item={item}/>
          ))}
        </div>
      );
    }
  }

  const ShowResultStripped = () => {
    if (loadingFinish) {
      return (
        <div> 
          <h2>Analysis Results</h2>
          <h3>Stripped Binary File.</h3>
          <h3>{binaryAnalysisResult.length} Functions.</h3>
          {binaryAnalysisResult.map((item, idx) => (
            <StrippedResult key={idx} idx={idx} item={item}/>
          ))}
        </div>
      );
    }
  }

  const Main = () => {
    return (
      <div>
        <header>
          <h1>AsmDepictor</h1>
          <h3>AsmDepictor information</h3>
          <span>The file size limit is 2mb, and the analysis time limit is 60 seconds.</span><br></br>
          <span>If there is a timeout, upload a smaller file.</span><br></br>
          <span>The file formats that can be analyzed are ELF, 64-bit, and x86-64.</span>
        </header>

        <hr></hr>

        <div className={styles.wrapper}>
          <section>
            <h4>Upload your binary file</h4>
            <input type="text" disabled="disabled" value={selectedFileName}/>
            <label className={styles.upload_label} htmlFor={isLoading ? null : "file"}>Upload</label>
            <input className={styles.upload_input} type="file" id="file" name="file" onChange={onFileChange}/>
            <input className={styles.upload_delete_button} type="button" value="Delete" onClick={onFileDelete}/>
          </section>

          <section>
            <h4>Or check out one of these samples</h4>
            <select disabled={isLoading} value={selectExampleFile} onChange={SelectBinaryFile}>
              <option value="0">Select Example File</option>
              <option value="1">{example_list[1]}</option>
              <option value="2">{example_list[2]}</option>
              <option value="3">{example_list[3]}</option>
              <option value="4">{example_list[4]}</option>
              <option value="5">{example_list[5]}</option>
              <option value="6">{example_list[6]}</option>
              <option value="7">{example_list[7]}</option>
              <option value="8">{example_list[8]}</option>
              <option value="9">{example_list[9]}</option>
            </select>
            <input className={styles.upload_delete_button} type="button" value="Delete" onClick={onSelectedFileDelete}/>
          </section>

          <section>
            <h4>Select the model</h4>
            <select disabled={isLoading} value={selectModel} onChange={SelectModel}>
              <option value="0">Select Model</option>
              <option value="1">{model_list[1]}</option>
              <option value="2">{model_list[2]}</option>
              <option value="3">{model_list[3]}</option>
            </select>
          </section>

          <button
            className={styles.btn}
            onClick={AnalysisButtonClick}>
            Analysis
          </button>
        </div>
      </div>
    )
  }

  const AnalysisInfo = () => {
    return (
      <div>
        <p className={styles.analysis_info}>
          Analyzing {selectedFileNameForNoRendering}... {sec}s
          <br></br>
          Analyzing binary file{analysisFinish ? "... done" : ".".repeat((sec % 3) + 1)}
          <br></br>
          {!analysisFinish  ? "Predicting function name..." : predictionFinish ? "Predicting function name... done" : "Predicting function name" + ".".repeat((sec % 3) + 1)}
        </p>
      </div>
    )
  }

  // 전체 렌더링
  return (
    <div className={styles.textfont}>
      <Main/>
      {(isLoading || loadingFinish) && <AnalysisInfo />}
      {loadingFinish && (isStripped ? <ShowResultStripped/>: <ShowResult/>)}
    </div>
  )
}

export default App;
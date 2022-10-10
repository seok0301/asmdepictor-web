import argparse
import subprocess
import os
import shutil


def ghidra(analyzer, input, flag):
    if os.path.exists(f"ghidra{os.sep}tmp"):
        shutil.rmtree(f"ghidra{os.sep}tmp")
    os.mkdir(f"ghidra{os.sep}tmp")
    cmd = []
    if flag == str(1):
        
        if not os.path.exists(input):
            print("[-] input path does not exist")
            return
        
        cmd = [
            analyzer,
            f"ghidra{os.sep}tmp",
            "analyze",
            "-prescript",
            "ghidra/pre.py",
            "-postscript",
            "ghidra/post.py",
            "-import",
            input,
        ]
        
    elif flag == str(2):
        cmd = [
            analyzer,
            f"ghidra{os.sep}tmp",
            input,  # ex) analyze/sample
            "-postscript",
            "ghidra/post.py",
            "-process",
            "\*",
            "-noanalysis"
        ]
        print(cmd)
    subprocess.run(cmd)
    return

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Executable file Analyzer with Ghidra"
    )
    parser.add_argument("analyzer", help="analyzeHeadless path or idat path")
    parser.add_argument("input", nargs="+",
                        help="Sample file or directory ex)analyze , if flag 2 project_name ex)analyze/sample")
    parser.add_argument(
        "flag", help="noDecompiler 1, open project 2, 1 Option is recommended.")
    args = parser.parse_args()

    for input in args.input:
        ghidra(args.analyzer, input, args.flag)
# -*- coding: utf8 -*-
import os
import platform
import json
from binascii import hexlify
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.app.util.bin.format.elf import *
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor

from ghidra.app.util.opinion import ElfLoader
import generic.continues.RethrowContinuesFactory
import ghidra.app.util.bin.format.elf.ElfDefaultGotPltMarkup
import generic.continues.GenericFactory
import ghidra.app.util.bin.format.elf
import ghidra.app.util.bin.MemoryByteProvider
import ghidra.app.util.importer.MessageLogContinuesFactory
from ghidra.util.task import ConsoleTaskMonitor


PLATFORM = platform.system()
    
getprocaddress_symbol = ""
getprocaddress_check = False
getprocaddress_list = []

oep = 0

API_NAME = 2
API_DLL = 1
API_ADDR = 0

sections = []


def perm(val):
    def r(val):
        return "r" if val & 4 else "-"

    def w(val):
        return "w" if val & 2 else "-"

    def x(val):
        return "x" if val & 1 else "-"

    return r(val) + w(val) + x(val)


def getAddress(offset):
    return (
        currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)
    )


def getString(addr):
    mem = currentProgram.getMemory()
    core_name_str = ""
    while True:
        byte = mem.getByte(addr.add(len(core_name_str)))
        if byte == 0:
            return core_name_str
        core_name_str += chr(byte)


def getHexAddress(input):
    try:
        address = hex(int(str(input), 16))
    except:
        address = 0
    return address


def getCurrentItem(name):
    try:
        cur = (item for item in db["ghidra"]
               [filename] if item["name"] == name).next()
    except:
        cur = None
    return cur
#0x805b860
#0x80c3910
def getXref(func):
    addr = func.getEntryPoint()
    name = func.getName()
    entry_point = func.getEntryPoint()
    maxaddress = func.getBody().getMaxAddress()
    references = getReferencesTo(entry_point)
    if not references:
        return

    xref = [
        {"from": getHexAddress(x.fromAddress),
         "to": getHexAddress(x.toAddress)}
        for x in references
    ]

    obj = {
        "name": str(name),
        "addr": getHexAddress(addr),
        "xref": xref,
        "ret": getHexAddress(maxaddress),
    }
    db["ghidra"][filename].append(obj)


def getInstInformation(func):
    inst_sequential = []
    pcode_sequential = []
    insts = []
    name = func.getName()
    cur = getCurrentItem(name)
    if not cur:
        return

    instr = getInstructionAt(func.getBody().getMinAddress())
    if not instr:
        return

    addrSet = func.getBody()
    codeUnits = listing.getCodeUnits(addrSet, True)
    for codeUnit in codeUnits:
        insts.append(hexlify(codeUnit.getBytes()))

    #while instr and instr.getMinAddress() <= func.getBody().getMaxAddress():
    #    if func.getBody().contains(instr.getMinAddress()):
    #        for pcode_op in instr.getPcode():
    #            pcode_name = pcode_op.getMnemonic()
    #            pcode_sequential.append(pcode_name)

        instr = instr.getNext()
    insts = ",".join(insts)
    # obj = {"sequential": inst_sequential, "bytecode": insts}
    #obj = {"sequential": pcode_sequential, "bytecode": insts}
    #obj = {"bytecode": insts}
    cur["inst"] = insts


def getIAT(currentProgram):
    global oep
    try:
        image_base = currentProgram.getMinAddress()
        provider = ghidra.app.util.bin.MemoryByteProvider(
            currentProgram.getMemory(), currentProgram.getImageBase()
        )
        """
        pe = PortableExecutable.createPortableExecutable(
            generic.continues.RethrowContinuesFactory.INSTANCE,
            provider,
            ghidra.app.util.bin.format.elf.PortableExecutable.SectionLayout.MEMORY,
            1,
            0,
        )
        """
        ntHeader = ElfConstants.getNTHeader() #file header
        optionalHeader = ntHeader.getOptionalHeader() #OptionalHeader structure member
        dataDirectories = optionalHeader.getDataDirectories()
        idd = dataDirectories[OptionalHeader.IMAGE_DIRECTORY_ENTRY_IMPORT]
        iat_ptrs = []
        image_base = int("0x" + str(image_base), 16)
        for importInfo in idd.getImports():
            add = "0x{0:x}".format(importInfo.getAddress())
            addr = image_base + int(add, 16)

            iat_ptrs.append(
                [
                    hex(addr),
                    str(importInfo.getDLL()),
                    str(importInfo.getName()),
                ]
            )

        addressofentrypoint = optionalHeader.getAddressOfEntryPoint()
        imagebase = optionalHeader.getImageBase()
        oep = hex(int(addressofentrypoint) + int(imagebase))
        print(getHexAddress(oep))
    except:
        iat_ptrs = ["ERROR"]
    return iat_ptrs


def getXrefIAT(iat_ptr):
    global sections
    xref_list = []
    xrefs = getReferencesTo(getAddress(iat_ptr[API_ADDR]))
    opcode = ""
    operand = ""
    textFlag = 0
    sectionName = ""
    if "ERROR" in iat_ptr:
        xref_list.append({"References": "PE parser Error"})
    else:
        for xref in xrefs:
            funs = getFunctionContaining(xref.getFromAddress())
            if funs == None:
                bb = blockModel.getCodeBlocksContaining(
                    xref.getFromAddress(), monitor)
                funs_start = bb[0].minAddress
                funs_end = bb[0].maxAddress

            instr = getInstructionAt(xref.getFromAddress())
            for section in sections:
                if (getHexAddress(section['Start']) < getHexAddress(oep)
                        and getHexAddress(section['End']) > getHexAddress(oep)):
                    if (
                        section["Start"] < xref.getFromAddress()
                        and section["End"] > xref.getFromAddress()
                    ):
                        textFlag = 1
                        sectionName = section['Name']

            try:

                opcode = instr.getMnemonicString().lower()
                if opcode in ["jmp"]:
                    ptr = xref.getFromAddress()
                    data = [
                        str(ptr),
                        str(iat_ptr[API_DLL]),
                        str(iat_ptr[API_NAME]),
                    ]
                    getXrefIAT(data)
                    return
                opcode = str(instr.getMnemonicString())
                operand = ""
                operand_type = ""
                if list(instr.getOpObjects(0)):
                    operand = str(list(instr.getOpObjects(0)))[1:-1]
                    operand_type = str(instr.getOperandRefType(0))
                if list(instr.getOpObjects(1)):
                    operand += ", " + str(list(instr.getOpObjects(1)))[1:-1]
                    operand_type += ", " + str(instr.getOperandRefType(1))
                try:
                    xref_list.append(
                        {
                            "func_name": str(funs.getName()),
                            "func_start": str(funs.getBody().getMinAddress()),
                            "func_end": str(funs.getBody().getMaxAddress()),
                            "src": str(xref.getFromAddress()),
                            "type": str(xref.getReferenceType()),
                            "inst": str(instr),
                            "opcode": opcode,
                            "operand": operand,
                            "api": iat_ptr[API_NAME],
                            "inTextFlag": textFlag,
                            "textSectionName": sectionName
                        }
                    )
                except:
                    xref_list.append(
                        {
                            "func_name": str(funs.getName()),
                            "func_start": str(funs_start),
                            "func_end": str(funs_end),
                            "src": str(xref.getFromAddress()),
                            "type": str(xref.getReferenceType()),
                            "inst": str(instr),
                            "opcode": opcode,
                            "operand": operand,
                            "api": iat_ptr[API_NAME],
                            "inTextFlag": textFlag,
                            "textSectionName": sectionName
                        }
                    )
            except:
                xref_list.append(
                    {
                        "func_name": "NotFound",
                        "func_start": "NotFound",
                        "func_end": "NotFound",
                        "src": str(xref.getFromAddress()),
                        "type": str(xref.getReferenceType()),
                        "inst": "None",
                        "opcode": "None",
                        "operand": "None",
                        "api": iat_ptr[API_NAME],
                        "inTextFlag": textFlag,
                        "textSectionName": sectionName
                    }
                )
    obj = xref_list
    if obj:
        db["xref_list"][filename].append(obj)


def getSections():
    global sections
    blocks = currentProgram.getMemory().getBlocks()
    section_list = []
    for block in blocks:
        section_list.append(
            {
                "Name": str(block.getName()),
                "Start": str(block.start),
                "End": str(block.end),
                "Length": str(block.getSize()),
                "Perm": perm(block.getPermissions()),
                "initialized": str(block.isInitialized()),
            }
        )
        sections.append(
            {
                "Start": block.start,
                "End": block.end,
                "Name": str(block.getName())
            })

    db["section"][filename].append(section_list)


def getDecompileInfo(func):
    name = func.getName()
    cur = getCurrentItem(name)
    if not cur:
        return
    try:
        function = getGlobalFunctions(name)[0]
        results = ifc.decompileFunction(function, 3, ConsoleTaskMonitor())
        obj = results.getDecompiledFunction().getC()
        cur["decompile"] = obj
    except:
        cur["decompile"] = "timeout"

def main():
    getSections()

    iat_ptrs = getIAT(getCurrentProgram())
    for iat_ptr in iat_ptrs:
        getXrefIAT(iat_ptr)
    
    fm = getCurrentProgram().getFunctionManager()
    for func in fm.getFunctions(True):
        getXref(func)
        getInstInformation(func)
        # getDecompileInfo(func)

def createFolder(directory):
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
    except OSError:
        print("Error: Creating directory. " + directory)


def store(filename, db):
    names = ["output_inst", "output_xref", "output_section"]
    jsonnames = ["ghidra", "xref_list", "section"]
    path = ""
    for i, name in enumerate(names):
        createFolder(name)
        if PLATFORM == "Windows":
            path = "{}\\{}.json".format(name, filename)
        else:
            path = "{}//{}.json".format(name, filename)
        with open(path, "w") as fd:
            fd.write(
                json.dumps(
                    db[jsonnames[i]],
                    sort_keys=True,
                    indent=4,
                )
            )


if __name__ == "__main__":

    program = getCurrentProgram()
    listing = program.getListing()
    blockModel = BasicBlockModel(program)
    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    ifc.openProgram(program)
    filename = str(program.getName())
    db = {}
    db["xref_list"] = {filename: []}
    db["ghidra"] = {filename: []}
    db["section"] = {filename: []}
    db["decompile"] = {filename: []}
    main()
    store(filename, db)

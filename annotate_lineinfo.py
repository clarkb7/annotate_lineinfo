"""
Annotate IDA with source and line number information from a PDB

Copyright (c) 2019 Branden Clark [github.com/clarkb7]
MIT License, see LICENSE for details.
"""

import os
import sys
import argparse

import logging
logging.basicConfig(format='%(asctime)s | %(name)s | %(levelname)s | %(message)s')
logger = logging.getLogger(__name__)

DEFAULT_MSDIA_VERSION="msdia140"

def dia_enum_iter(enum):
    """Turn an IDiaEnum* object into a python generator"""
    for i in xrange(enum.count):
        yield enum.Next(1)[0]

def dia_iter_funcs(msdia, session):
    """Iterate all function symbols"""
    enumcomp = session.globalScope.findChildren(msdia.SymTagCompiland, None, 0)
    for comp in dia_enum_iter(enumcomp):
        # Skip compilands without source files
        if comp.sourceFileName is None:
            continue
        logger.debug("--------------- {} ---------------".format(comp.sourceFileName))
        enumfunc = comp.findChildren(msdia.SymTagFunction, None, 0)
        for func in dia_enum_iter(enumfunc):
            yield func

def dia_init(binary, msdia_ver=DEFAULT_MSDIA_VERSION):
    """Initialize MSDIA com API session"""
    from comtypes.client import GetModule, CreateObject
    from ctypes.util import find_library
    import ctypes
    import _ctypes
    # Find path to dia lib
    dllpath = find_library(msdia_ver)
    if dllpath is None:
        logger.error("Could not find {}.dll".format(msdia_ver))
        exit(1)
    logger.debug("Found {} at {}".format(msdia_ver, dllpath))
    # Ready comtypes interface
    msdia = GetModule(dllpath)
    dataSource = CreateObject(msdia.DiaSource, interface=msdia.IDiaDataSource)
    # Load debug info
    ext = os.path.splitext(binary)[1]
    try:
        if ext == '.pdb':
            dataSource.loadDataFromPdb(binary)
        else:
            dataSource.loadDataForExe(binary,os.path.dirname(binary), None)
    except _ctypes.COMError as e:
        hr = ctypes.c_uint(e[0]).value
        if hr == 0x806D0005: # E_PDB_NOT_FOUND
            logger.error("Unable to locate PDB")
        elif hr == 0x806D0012: # E_PDB_FORMAT
            logger.error("Invalid or obsolete file format")
        else:
            logger.error("Unknown exception loading PDB info: {}".format(e))
        exit(1)
    session = dataSource.openSession()
    return msdia, dataSource, session

def dia_iter_lineinfo(binary, msdia_ver=DEFAULT_MSDIA_VERSION):
    """Iterate IDiaLineNumber symbol info for each function in @binary"""
    msdia,dataSource,session = dia_init(binary,msdia_ver=msdia_ver)
    for func in dia_iter_funcs(msdia,session):
        enumlines = session.findLinesByRVA(func.relativeVirtualAddress, func.length)
        for line in dia_enum_iter(enumlines):
            logger.debug("[{:08X}-{:08X}] {}:{}:{}".format(
                func.relativeVirtualAddress, func.relativeVirtualAddress+func.length,
                line.compiland.sourceFileName, func.name, line.lineNumber))
            yield func,line

def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', help="Path to exe or pdb to analyze")
    parser.add_argument("-v", "--verbose",action="store_true")
    parser.add_argument("--msdia",help="msdia version to use (default: %(default)s)",
        default=DEFAULT_MSDIA_VERSION)
    args = parser.parse_args(argv)

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    for _ in dia_iter_lineinfo(args.binary,msdia_ver=args.msdia):
        pass

try:
    import idaapi
except ImportError:
    # No IDA here
    if __name__ == "__main__":
        main(sys.argv[1:])
else:
    # Run from within IDA
    def ida_anterior_comment(ea, comment):
        """Add anterior comment @comment at @ea"""
        # Ensure we don't duplcate the comment
        cur_cmt = idaapi.get_extra_cmt(ea, idaapi.E_PREV)
        if cur_cmt is not None and comment in cur_cmt:
            return
        # Add the comment
        idaapi.add_long_cmt(ea, True, comment)

    def ida_annotate_lineinfo(binary, msdia_ver=DEFAULT_MSDIA_VERSION):
        """Annotate IDA with source/line number information for @binary"""
        for func,line in dia_iter_lineinfo(binary,msdia_ver=msdia_ver):
            ea = idaapi.get_imagebase()+line.relativeVirtualAddress
            cmt = "{}:{}:{}".format(line.compiland.sourceFileName,func.name,line.lineNumber)
            ida_anterior_comment(ea, cmt)

    if __name__ == "__main__":
        logger.setLevel(logging.DEBUG)
        ida_annotate_lineinfo(idaapi.get_input_file_path())

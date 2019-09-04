#!/usr/bin/env python
'''

PS3 Syscon Loader by SocraticBliss (R)

Dedicated to zecoxao <3

ps3_syscon_loader.py: IDA loader for reading Sony PlayStation(R) 3 Syscon Firmware files

'''

from idaapi import *
from idc import *

import idaapi
import idc
import struct

# Load Processor Details...
def processor(processor, til):
    
    # Processor
    idc.set_processor_type(processor, SETPROC_LOADER)
    
    # Assembler
    idc.set_target_assembler(0x0)
    
    # Type Library
    idc.add_default_til(til)
    
    # Compiler
    idc.set_inf_attr(INF_COMPILER, COMP_GNU)
    
    # Loader Flags
    idc.set_inf_attr(INF_LFLAGS, LFLG_PC_FLAT)
    
    # Assume GCC3 names
    idc.set_inf_attr(INF_DEMNAMES, DEMNAM_GCC3)
    
    # Analysis Flags
    idc.set_inf_attr(INF_AF, 0xC7FFFFD7)

# PROGRAM START

# Open File Dialog...
def accept_file(f, n):
    
    try:
        if not isinstance(n, (int, long)) or n == 0:
            return 'PS3 - Syscon Firmware - ' if f.read(4) == '\x18\xF0\x9F\xE5' else 0
    
    except:
        pass

# Load Input Binary...
def load_file(f, neflags, format):
    
    print('# PS3 Syscon Loader')
    
    # PS3 Syscon Processor and Library
    processor('arm', 'gnulnx_arm')
    
    print('# Creating ROM Segment...')
    address = 0x0
    end = address + f.size()
    
    f.file2base(address, address, end, FILEREG_PATCHABLE)
    idaapi.add_segm(0x0, address, end, 'ROM', 'CODE', 0x0)
    
    # Processor Specific Segment Details
    idc.set_segm_addressing(address, 0x1)
    idc.set_segm_alignment(address, saAbs)
    idc.set_segm_combination(address, scPriv)
    idc.set_segm_attr(address, SEGATTR_PERM, SEGPERM_MAXVAL)
    idc.set_default_sreg_value(address, 'T', 0x0)
    idc.set_default_sreg_value(address, 'DS', 0x1)
    
    print('# Waiting for the AutoAnalyzer to Complete...')
    idaapi.auto_wait()
    
    # Create some missing functions...
    while address < end:
        address = idaapi.find_binary(address, end, '?? B5', 0x10, SEARCH_DOWN)
        
        idaapi.create_insn(address)
        
        # Pablo escobar
        if idc.print_insn_mnem(address + 2) in ['LDR', 'MOVS', 'SUB']:
            idc.add_func(address)
        else:
            idaapi.do_unknown(address)
        
        address += 4
    
    print('# Done!')
    return 1

# PROGRAM END
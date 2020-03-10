#!/usr/bin/python2.7
import pefile
import sys
import collections
from capstone import *
from capstone.x86 import *

def get_init_address(code_dump, code_addr):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    md.skipdata = True
    disasm = md.disasm(code_dump, code_addr)
    current_fn = 0
    mov_num = 0
    for i in disasm:
        if i.mnemonic == "nop":
            current_fn = i.address+1
            mov_num = 0
        if i.mnemonic == "push" and i.op_str == "ebp":
            i = next(disasm)
            if i.mnemonic == "mov" and i.op_str == "ebp, esp":
                current_fn = i.address-1
                mov_num = 0
                #print "fn"
        if i.mnemonic == "mov" and i.op_str.find("dword ptr [eax + 0x10]") == 0:
            mov_num += 1
        if mov_num > 150:
            return current_fn
    print("disasm end %x" % (current_fn))
    return 0

def dump_packets(code_dump, code_addr):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    disasm = md.disasm(code_dump, code_addr)
    last_imm = 0
    pkts = {}
    for i in disasm:
        if i.mnemonic == "ret":
            break
        if i.mnemonic == "mov":
            if i.operands[1].type == X86_OP_IMM and i.operands[0].type == X86_OP_MEM:
                if i.op_str.find("dword ptr [eax + 0x10]") == 0:
                    pkts[last_imm] = int(i.operands[1].value.imm)
                else:
                    last_imm = int(i.operands[1].value.imm)
            
    return pkts

def find_enter_packet(buf, base, sigaddr):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    md.skipdata = True
    disasm = md.disasm(buf, base)
    found_push = False
    skipped_ins = 0
    for i in disasm:
        if skipped_ins > 20:
            break
        if found_push == True:
            skipped_ins += 1
            if i.mnemonic == "mov" and i.op_str.find("word ptr [") == 0:
                if i.operands[1].type == X86_OP_IMM:
                    return int(i.operands[1].value.imm)
        if i.mnemonic == "push":
            if i.operands[0].type == X86_OP_IMM and int(i.operands[0].value.imm) == sigaddr:
                found_push = True
    return 0

def find_enter_sig(buf, base):
    #print len(buf)
    off = str(buf).find("PACKET_CZ_ENTER")
    if off == -1:
        off = 0
    else:
        off += base
    return off

def get_enter_packet(file_path):
    pe = pefile.PE(file_path)
    addr = 0
    for section in pe.sections:
        if section.Name.find(".data") == 0:
            data = section.get_data()
            base = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
            addr = find_enter_sig(data,base)
            if addr != 0:
                break
    if addr == 0:
        return 0
    eop = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    code_section = pe.get_section_by_rva(eop)
    code_dump = code_section.get_data()
    code_addr = pe.OPTIONAL_HEADER.ImageBase + code_section.VirtualAddress
    return find_enter_packet(code_dump, code_addr, addr)
    

def get_pks(file_path):
    pe = pefile.PE(file_path)

    eop = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    code_section = pe.get_section_by_rva(eop)

    code_dump = code_section.get_data()

    code_addr = pe.OPTIONAL_HEADER.ImageBase + code_section.VirtualAddress
    #print("base %x size %d" % (code_addr, len(code_dump)))
    initfn = get_init_address(code_dump, code_addr)
    if initfn == 0:
        print "cant find init fn"
        exit()
    print("%x" % (initfn))
    off = initfn - code_addr
    pks = dump_packets(code_dump[off:], initfn)
    return pks

def diff(client,server):
    p1 = get_pks(client)
    p2 = get_pks(server)

    print("Client has %d packets" % (len(p1)))
    print("Server has %d packets" % (len(p2)))

    if len(p1) < len(p1):
        print "Warning: server has less packets than client"

    client_does_not_have = 0
    server_does_not_have = 0
    diffs = 0

    for pk in p1:
        if pk in p2:
            if not p1[pk] == p2[pk]:
                print '{:04X}: Client {:d} Server {:d}'.format(pk, p1[pk], p2[pk])
                diffs += 1
        else:
            server_does_not_have += 1

    for pk in p2:
        if pk not in p1:
            client_does_not_have += 1
            #print("Pk %x(%d): client does not have it" % (pk, p2[pk]))
    print("%d diffs" % (diffs))
    print("Also: client does not have %d packets" % (client_does_not_have))
    print("Also: server does not have %d packets" % (server_does_not_have))


def dump(exe):
    p1 = get_pks(exe)
    ordered = collections.OrderedDict(p1)
    for pkt in ordered:
        print '{:04X} {:d}'.format(pkt, ordered[pkt])
    #

def enter(exe):
    pkt = get_enter_packet(exe)
    print 'Enter packet {:04X}'.format(pkt)

if len(sys.argv) < 2:
    print "usage: pl.py dump|diff|enter args"
    exit()

mode = sys.argv[1]
if mode == "diff":
    if len(sys.argv) < 4:
        print "usage: pl.py diff client.exe server.exe"
        exit()
    diff(sys.argv[2],sys.argv[3])
elif mode == "dump":
    if len(sys.argv) < 3:
        print "usage: pl.py dump client_or_server.exe"
        exit()
    dump(sys.argv[2])
elif mode == "enter":
    if len(sys.argv) < 3:
        print "usage: pl.py enter client.exe"
        exit()
    enter(sys.argv[2])
else:
    print "usage: pl.py dump|diff|enter args"
    exit()


from idaapi import *
import copy

def SIGNEXT(x, b):
    m = 1 << (b - 1)
    x = x & ((1 << b) - 1)
    return (x ^ m) - m


class DecodingError(Exception):
    pass

class openrisc_processor_t(processor_t):
    id = 0x8000 + 0x5571C
    flag = PR_SEGS | PRN_HEX | PR_RNAMESOK | PR_NO_SEGMOVE | PR_USE32 | PR_DEFSEG32
    cnbits = 8
    dnbits = 8
    author = "Deva"
    psnames = ["OpenRISC"]
    plnames = ["OpenRISC"]
    segreg_size = 0
    instruc_start = 0
    assembler = {
        "flag": ASH_HEXF0 | ASD_DECF0 | ASO_OCTF5 | ASB_BINF0 | AS_N2CHR,
        "uflag": 0,
        "name": "OpenRISC asm",
        "origin": ".org",
        "end": ".end",
        "cmnt": ";",
        "ascsep": '"',
        "accsep": "'",
        "esccodes": "\"'",
        "a_ascii": ".ascii",
        "a_byte": ".byte",
        "a_word": ".word",
        "a_bss": "dfs %s",
        "a_seg": "seg",
        "a_curip": "PC",
        "a_public": "",
        "a_weak": "",
        "a_extrn": ".extern",
        "a_comdef": "",
        "a_align": ".align",
        "lbrace": "(",
        "rbrace": ")",
        "a_mod": "%",
        "a_band": "&",
        "a_bor": "|",
        "a_xor": "^",
        "a_bnot": "~",
        "a_shl": "<<",
        "a_shr": ">>",
        "a_sizeof_fmt": "size %s",
    }

    reg_names = regNames = [
        "r0", "r1", "r2", "r3", "r4",
        "r5", "r6", "r7", "r8",
        "r9", "r10", "r11", "r12", "r13",
        "r14", "r15", "r16", "r17", "r18", "r19", "R20", "R21",
        "r22", "r23", "r24", "r25", "r26",
        "r27", "r28", "r29", "r30", "r31",
        #virutal 
        "CS", "DS"
    ]

    instruc = instrs = [{'name': 'l.add', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'l.add rD,rA,rB'},
        {'name': 'l.addc', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'l.addc rD,rA,rB'},
        {'name': 'l.addi', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'l.addi rD,rA,I'},
        {'name': 'l.addic', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'l.addic rD,rA,I'},
        {'name': 'l.and', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'l.and rD,rA,rB'},
        {'name': 'l.andi', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'l.andi rD,rA,K'},
        {'name': 'l.bf', 'feature': CF_USE1, 'cmt': 'l.bf N'},
        {'name': 'l.bnf', 'feature': CF_USE1, 'cmt': 'l.bnf N'},
        {'name': 'l.cmov', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'l.cmov rD,rA,rB'},
        {'name': 'l.csyn', 'feature': 0, 'cmt': 'l.csync'},
        {'name': 'l.cust', 'feature': 0, 'cmt': 'l.cust1'},
        {'name': 'l.cust', 'feature': 0, 'cmt': 'l.cust2'},
        {'name': 'l.cust', 'feature': 0, 'cmt': 'l.cust3'},
        {'name': 'l.cust', 'feature': 0, 'cmt': 'l.cust4'},
        {'name': 'l.cust5', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4 | CF_USE5, 'cmt': 'l.cust5 rD,rA,rB,L,K'},
        {'name': 'l.cust', 'feature': 0, 'cmt': 'l.cust6'},
        {'name': 'l.cust', 'feature': 0, 'cmt': 'l.cust7'},
        {'name': 'l.cust', 'feature': 0, 'cmt': 'l.cust8'},
        {'name': 'l.div', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'l.div rD,rA,rB'},
        {'name': 'l.divu', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'l.divu rD,rA,rB'},
        {'name': 'l.extbs', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.extbs rD,rA'},
        {'name': 'l.extbz', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.extbz rD,rA'},
        {'name': 'l.exths', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.exths rD,rA'},
        {'name': 'l.exthz', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.exthz rD,rA'},
        {'name': 'l.extws', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.extws rD,rA'},
        {'name': 'l.extwz', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.extwz rD,rA'},
        {'name': 'l.ff1', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.ff1 rD,rA,rB'},
        {'name': 'l.fl1', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.fl1 rD,rA,rB'},
        {'name': 'l.j', 'feature': CF_USE1, 'cmt': 'l.j N'},
        {'name': 'l.jal', 'feature': CF_USE1, 'cmt': 'l.jal N'},
        {'name': 'l.jalr', 'feature': CF_USE1, 'cmt': 'l.jalr rB'},
        {'name': 'l.jr', 'feature': CF_USE1, 'cmt': 'l.jr rB'},
        {'name': 'l.lbs', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.lbs rD,I(rA)'},
        {'name': 'l.lbz', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.lbz rD,I(rA)'},
        {'name': 'l.ld', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.ld rD,I(rA)'},
        {'name': 'l.lhs', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.lhs rD,I(rA)'},
        {'name': 'l.lhz', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.lhz rD,I(rA)'},
        {'name': 'l.lwa', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.lwa rD,I(rA)'},
        {'name': 'l.lws', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.lws rD,I(rA)'},
        {'name': 'l.lwz', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.lwz rD,I(rA)'},
        {'name': 'l.mac', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.mac rA,rB'},
        {'name': 'l.maci', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.maci rA,I'},
        {'name': 'l.macrc', 'feature': CF_USE1, 'cmt': 'l.macrc rD'},
        {'name': 'l.macu', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.macu rA,rB'},
        {'name': 'l.mfspr', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'l.mfspr rD,rA,K'},
        {'name': 'l.movhi', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.movhi rD,K'},
        {'name': 'l.msb', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.msb rA,rB'},
        {'name': 'l.msbu', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.msbu rA,rB'},
        {'name': 'l.msyn', 'feature': 0, 'cmt': 'l.msync'},
        {'name': 'l.mtspr', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'l.mtspr rA,rB,K'},
        {'name': 'l.mul', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'l.mul rD,rA,rB'},
        {'name': 'l.muld', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.muld rA,rB'},
        {'name': 'l.muldu', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.muldu rA,rB'},
        {'name': 'l.muli', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'l.muli rD,rA,I'},
        {'name': 'l.mulu', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'l.mulu rD,rA,rB'},
        {'name': 'l.nop', 'feature': CF_USE1, 'cmt': 'l.nop K'},
        {'name': 'l.or', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'l.or rD,rA,rB'},
        {'name': 'l.ori', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'l.ori rD,rA,K'},
        {'name': 'l.psyn', 'feature': 0, 'cmt': 'l.psync'},
        {'name': 'l.rf', 'feature': 0, 'cmt': 'l.rfe'},
        {'name': 'l.ror', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'l.ror rD,rA,rB'},
        {'name': 'l.rori', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'l.rori rD,rA,L'},
        {'name': 'l.sb', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.sb I(rA),rB'},
        {'name': 'l.sd', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.sd I(rA),rB'},
        {'name': 'l.sfeq', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.sfeq rA,rB'},
        {'name': 'l.sfeqi', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.sfeqi rA,I'},
        {'name': 'l.sfges', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.sfges rA,rB'},
        {'name': 'l.sfgesi', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.sfgesi rA,I'},
        {'name': 'l.sfgeu', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.sfgeu rA,rB'},
        {'name': 'l.sfgeui', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.sfgeui rA,I'},
        {'name': 'l.sfgts', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.sfgts rA,rB'},
        {'name': 'l.sfgtsi', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.sfgtsi rA,I'},
        {'name': 'l.sfgtu', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.sfgtu rA,rB'},
        {'name': 'l.sfgtui', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.sfgtui rA,I'},
        {'name': 'l.sflesi', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.sflesi rA,I'},
        {'name': 'l.sfleu', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.sfleu rA,rB'},
        {'name': 'l.sfleui', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.sfleui rA,I'},
        {'name': 'l.sflts', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.sflts rA,rB'},
        {'name': 'l.sfltsi', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.sfltsi rA,I'},
        {'name': 'l.sfltu', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.sfltu rA,rB'},
        {'name': 'l.sfltui', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.sfltui rA,I'},
        {'name': 'l.sfne', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.sfne rA,rB'},
        {'name': 'l.sfnei', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.sfnei rA,I'},
        {'name': 'l.sh', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.sh I(rA),rB'},
        {'name': 'l.sll', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'l.sll rD,rA,rB'},
        {'name': 'l.slli', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'l.slli rD,rA,L'},
        {'name': 'l.sra', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'l.sra rD,rA,rB'},
        {'name': 'l.srai', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'l.srai rD,rA,L'},
        {'name': 'l.srl', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'l.srl rD,rA,rB'},
        {'name': 'l.srli', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'l.srli rD,rA,L'},
        {'name': 'l.sub', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'l.sub rD,rA,rB'},
        {'name': 'l.sw', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.sw I(rA),rB'},
        {'name': 'l.swa', 'feature': CF_USE1 | CF_USE2, 'cmt': 'l.swa I(rA),rB'},
        {'name': 'l.sys', 'feature': CF_USE1, 'cmt': 'l.sys K'},
        {'name': 'l.trap', 'feature': CF_USE1, 'cmt': 'l.trap K'},
        {'name': 'l.xor', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'l.xor rD,rA,rB'},
        {'name': 'l.xori', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'l.xori rD,rA,I'},
        {'name': 'lf.add.d', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lf.add.d rD,rA,rB'},
        {'name': 'lf.add.s', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lf.add.s rD,rA,rB'},
        {'name': 'lf.cust1.d', 'feature': CF_USE1 | CF_USE2, 'cmt': 'lf.cust1.d rA,rB'},
        {'name': 'lf.cust1.s', 'feature': CF_USE1 | CF_USE2, 'cmt': 'lf.cust1.s rA,rB'},
        {'name': 'lf.div.d', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lf.div.d rD,rA,rB'},
        {'name': 'lf.div.s', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lf.div.s rD,rA,rB'},
        {'name': 'lf.ftoi.d', 'feature': CF_USE1 | CF_USE2, 'cmt': 'lf.ftoi.d rD,rA'},
        {'name': 'lf.ftoi.s', 'feature': CF_USE1 | CF_USE2, 'cmt': 'lf.ftoi.s rD,rA'},
        {'name': 'lf.itof.d', 'feature': CF_USE1 | CF_USE2, 'cmt': 'lf.itof.d rD,rA'},
        {'name': 'lf.itof.s', 'feature': CF_USE1 | CF_USE2, 'cmt': 'lf.itof.s rD,rA'},
        {'name': 'lf.madd.d', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lf.madd.d rD,rA,rB'},
        {'name': 'lf.madd.s', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lf.madd.s rD,rA,rB'},
        {'name': 'lf.mul.d', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lf.mul.d rD,rA,rB'},
        {'name': 'lf.mul.s', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lf.mul.s rD,rA,rB'},
        {'name': 'lf.rem.d', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lf.rem.d rD,rA,rB'},
        {'name': 'lf.rem.s', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lf.rem.s rD,rA,rB'},
        {'name': 'lf.sfeq.d', 'feature': CF_USE1 | CF_USE2, 'cmt': 'lf.sfeq.d rA,rB'},
        {'name': 'lf.sfeq.s', 'feature': CF_USE1 | CF_USE2, 'cmt': 'lf.sfeq.s rA,rB'},
        {'name': 'lf.sfge.d', 'feature': CF_USE1 | CF_USE2, 'cmt': 'lf.sfge.d rA,rB'},
        {'name': 'lf.sfge.s', 'feature': CF_USE1 | CF_USE2, 'cmt': 'lf.sfge.s rA,rB'},
        {'name': 'lf.sfgt.d', 'feature': CF_USE1 | CF_USE2, 'cmt': 'lf.sfgt.d rA,rB'},
        {'name': 'lf.sfgt.s', 'feature': CF_USE1 | CF_USE2, 'cmt': 'lf.sfgt.s rA,rB'},
        {'name': 'lf.sfle.d', 'feature': CF_USE1 | CF_USE2, 'cmt': 'lf.sfle.d rA,rB'},
        {'name': 'lf.sfle.s', 'feature': CF_USE1 | CF_USE2, 'cmt': 'lf.sfle.s rA,rB'},
        {'name': 'lf.sflt.d', 'feature': CF_USE1 | CF_USE2, 'cmt': 'lf.sflt.d rA,rB'},
        {'name': 'lf.sflt.s', 'feature': CF_USE1 | CF_USE2, 'cmt': 'lf.sflt.s rA,rB'},
        {'name': 'lf.sfne.d', 'feature': CF_USE1 | CF_USE2, 'cmt': 'lf.sfne.d rA,rB'},
        {'name': 'lf.sfne.s', 'feature': CF_USE1 | CF_USE2, 'cmt': 'lf.sfne.s rA,rB'},
        {'name': 'lf.sub.d', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lf.sub.d rD,rA,rB'},
        {'name': 'lf.sub.s', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lf.sub.s rD,rA,rB'},
        {'name': 'lv.add.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.add.b rD,rA,rB'},
        {'name': 'lv.add.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.add.h rD,rA,rB'},
        {'name': 'lv.adds.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.adds.b rD,rA,rB'},
        {'name': 'lv.adds.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.adds.h rD,rA,rB'},
        {'name': 'lv.addu.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.addu.b rD,rA,rB'},
        {'name': 'lv.addu.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.addu.h rD,rA,rB'},
        {'name': 'lv.addus.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.addus.b rD,rA,rB'},
        {'name': 'lv.addus.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.addus.h rD,rA,rB'},
        {'name': 'lv.all_eq.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.all_eq.b rD,rA,rB'},
        {'name': 'lv.all_eq.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.all_eq.h rD,rA,rB'},
        {'name': 'lv.all_ge.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.all_ge.b rD,rA,rB'},
        {'name': 'lv.all_ge.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.all_ge.h rD,rA,rB'},
        {'name': 'lv.all_gt.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.all_gt.b rD,rA,rB'},
        {'name': 'lv.all_gt.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.all_gt.h rD,rA,rB'},
        {'name': 'lv.all_le.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.all_le.b rD,rA,rB'},
        {'name': 'lv.all_le.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.all_le.h rD,rA,rB'},
        {'name': 'lv.all_lt.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.all_lt.b rD,rA,rB'},
        {'name': 'lv.all_lt.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.all_lt.h rD,rA,rB'},
        {'name': 'lv.all_ne.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.all_ne.b rD,rA,rB'},
        {'name': 'lv.all_ne.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.all_ne.h rD,rA,rB'},
        {'name': 'lv.and', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.and rD,rA,rB'},
        {'name': 'lv.any_eq.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.any_eq.b rD,rA,rB'},
        {'name': 'lv.any_eq.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.any_eq.h rD,rA,rB'},
        {'name': 'lv.any_ge.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.any_ge.b rD,rA,rB'},
        {'name': 'lv.any_ge.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.any_ge.h rD,rA,rB'},
        {'name': 'lv.any_gt.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.any_gt.b rD,rA,rB'},
        {'name': 'lv.any_gt.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.any_gt.h rD,rA,rB'},
        {'name': 'lv.any_le.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.any_le.b rD,rA,rB'},
        {'name': 'lv.any_le.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.any_le.h rD,rA,rB'},
        {'name': 'lv.any_lt.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.any_lt.b rD,rA,rB'},
        {'name': 'lv.any_lt.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.any_lt.h rD,rA,rB'},
        {'name': 'lv.any_ne.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.any_ne.b rD,rA,rB'},
        {'name': 'lv.any_ne.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.any_ne.h rD,rA,rB'},
        {'name': 'lv.avg.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.avg.b rD,rA,rB'},
        {'name': 'lv.avg.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.avg.h rD,rA,rB'},
        {'name': 'lv.cmp_eq.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.cmp_eq.b rD,rA,rB'},
        {'name': 'lv.cmp_eq.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.cmp_eq.h rD,rA,rB'},
        {'name': 'lv.cmp_ge.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.cmp_ge.b rD,rA,rB'},
        {'name': 'lv.cmp_ge.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.cmp_ge.h rD,rA,rB'},
        {'name': 'lv.cmp_gt.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.cmp_gt.b rD,rA,rB'},
        {'name': 'lv.cmp_gt.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.cmp_gt.h rD,rA,rB'},
        {'name': 'lv.cmp_le.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.cmp_le.b rD,rA,rB'},
        {'name': 'lv.cmp_le.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.cmp_le.h rD,rA,rB'},
        {'name': 'lv.cmp_lt.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.cmp_lt.b rD,rA,rB'},
        {'name': 'lv.cmp_lt.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.cmp_lt.h rD,rA,rB'},
        {'name': 'lv.cmp_ne.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.cmp_ne.b rD,rA,rB'},
        {'name': 'lv.cmp_ne.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.cmp_ne.h rD,rA,rB'},
        {'name': 'lv.cust', 'feature': 0, 'cmt': 'lv.cust1'},
        {'name': 'lv.cust', 'feature': 0, 'cmt': 'lv.cust2'},
        {'name': 'lv.cust', 'feature': 0, 'cmt': 'lv.cust3'},
        {'name': 'lv.cust', 'feature': 0, 'cmt': 'lv.cust4'},
        {'name': 'lv.madds.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.madds.h rD,rA,rB'},
        {'name': 'lv.max.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.max.b rD,rA,rB'},
        {'name': 'lv.max.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.max.h rD,rA,rB'},
        {'name': 'lv.merge.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.merge.b rD,rA,rB'},
        {'name': 'lv.merge.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.merge.h rD,rA,rB'},
        {'name': 'lv.min.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.min.b rD,rA,rB'},
        {'name': 'lv.min.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.min.h rD,rA,rB'},
        {'name': 'lv.msubs.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.msubs.h rD,rA,rB'},
        {'name': 'lv.muls.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.muls.h rD,rA,rB'},
        {'name': 'lv.nand', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.nand rD,rA,rB'},
        {'name': 'lv.nor', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.nor rD,rA,rB'},
        {'name': 'lv.or', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.or rD,rA,rB'},
        {'name': 'lv.pack.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.pack.b rD,rA,rB'},
        {'name': 'lv.pack.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.pack.h rD,rA,rB'},
        {'name': 'lv.packs.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.packs.b rD,rA,rB'},
        {'name': 'lv.packs.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.packs.h rD,rA,rB'},
        {'name': 'lv.packus.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.packus.b rD,rA,rB'},
        {'name': 'lv.packus.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.packus.h rD,rA,rB'},
        {'name': 'lv.perm.n', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.perm.n rD,rA,rB'},
        {'name': 'lv.rl.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.rl.b rD,rA,rB'},
        {'name': 'lv.rl.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.rl.h rD,rA,rB'},
        {'name': 'lv.sll', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.sll rD,rA,rB'},
        {'name': 'lv.sll.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.sll.b rD,rA,rB'},
        {'name': 'lv.sll.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.sll.h rD,rA,rB'},
        {'name': 'lv.sra.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.sra.b rD,rA,rB'},
        {'name': 'lv.sra.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.sra.h rD,rA,rB'},
        {'name': 'lv.srl', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.srl rD,rA,rB'},
        {'name': 'lv.srl.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.srl.b rD,rA,rB'},
        {'name': 'lv.srl.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.srl.h rD,rA,rB'},
        {'name': 'lv.sub.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.sub.b rD,rA,rB'},
        {'name': 'lv.sub.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.sub.h rD,rA,rB'},
        {'name': 'lv.subs.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.subs.h rD,rA,rB'},
        {'name': 'lv.subu.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.subu.b rD,rA,rB'},
        {'name': 'lv.subu.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.subu.h rD,rA,rB'},
        {'name': 'lv.subus.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.subus.b rD,rA,rB'},
        {'name': 'lv.subus.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.subus.h rD,rA,rB'},
        {'name': 'lv.unpack.b', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.unpack.b rD,rA,rB'},
        {'name': 'lv.unpack.h', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.unpack.h rD,rA,rB'},
        {'name': 'lv.xor', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'lv.xor rD,rA,rB'}]

    instruc_end = len(instruc)

    def __init__(self):
        processor_t.__init__(self)
        self._init_instructions()
        self._init_registers()

    def _init_instructions(self):
        self.inames = {}
        for idx, ins in enumerate(self.instrs):
            self.inames[ins['name']] = idx

    def _init_registers(self):
        self.reg_ids = {}
        for i, reg in enumerate(self.reg_names):
            self.reg_ids[reg] = i
        self.regFirstSreg = self.regCodeSreg = self.reg_ids["CS"]
        self.regLastSreg = self.regDataSreg = self.reg_ids["DS"]

    def _read_cmd_dword(self):
        ea = self.cmd.ea + self.cmd.size
        dword = get_full_long(ea)
        self.cmd.size += 4
        return dword

    def _ana(self):
        cmd = self.cmd
        opcode = self._read_cmd_dword()
        op_m5_sl16_sr16 = ((opcode & 0x1f0000) >> 16)
        op_m16_sl0_sr0 = ((opcode & 0xffff) >> 0)
        op_m1_sl16_sr16 = ((opcode & 0x10000) >> 16)
        op_m6_sl0_sr0 = ((opcode & 0x3f) >> 0)
        op_m4_sl6_sr6 = ((opcode & 0x3c0) >> 6)
        op_m8_sl24_sr24 = ((opcode & 0xff000000) >> 24)
        op_m4_sl0_sr0 = ((opcode & 0xf) >> 0)
        op_m2_sl6_sr6 = ((opcode & 0xc0) >> 6)
        op_m8_sl0_sr0 = ((opcode & 0xff) >> 0)
        op_m5_sl21_sr21 = ((opcode & 0x3e00000) >> 21)
        op_m32_sl0_sr0 = ((opcode & 0xffffffff) >> 0)
        op_m17_sl0_sr0 = ((opcode & 0x1ffff) >> 0)
        op_m2_sl8_sr8 = ((opcode & 0x300) >> 8)
        op_m6_sl5_sr5 = ((opcode & 0x7e0) >> 5)
        op_m26_sl0_sr0 = ((opcode & 0x3ffffff) >> 0)
        op_m4_sl4_sr4 = ((opcode & 0xf0) >> 4)
        op_m11_sl0_sr0 = ((opcode & 0x7ff) >> 0)
        op_m5_sl11_sr11 = ((opcode & 0xf800) >> 11)
        op_m11_sl21_sr21 = ((opcode & 0xffe00000) >> 21)
        op_m5_sl0_sr0 = ((opcode & 0x1f) >> 0)
        op_m6_sl26_sr26 = ((opcode & 0xfc000000) >> 26)
        op_m5_sl21_sr10 = ((opcode & 0x3e00000) >> 10)
        op_m16_sl16_sr16 = ((opcode & 0xffff0000) >> 16)

        if (op_m4_sl0_sr0 == 0x0) and (op_m2_sl8_sr8 == 0x0) and (op_m6_sl26_sr26 == 0x38):
            cmd.itype = self.inames['l.add']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0x1) and (op_m2_sl8_sr8 == 0x0) and (op_m6_sl26_sr26 == 0x38):
            cmd.itype = self.inames['l.addc']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m6_sl26_sr26 == 0x27):
            cmd.itype = self.inames['l.addi']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_imm
            cmd[2].value = SIGNEXT(op_m16_sl0_sr0, 16)
            cmd[2].dtyp = dt_word
        elif (op_m6_sl26_sr26 == 0x28):
            cmd.itype = self.inames['l.addic']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_imm
            cmd[2].value = SIGNEXT(op_m16_sl0_sr0, 16)
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0x3) and (op_m2_sl8_sr8 == 0x0) and (op_m6_sl26_sr26 == 0x38):
            cmd.itype = self.inames['l.and']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m6_sl26_sr26 == 0x29):
            cmd.itype = self.inames['l.andi']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_imm
            cmd[2].value = op_m16_sl0_sr0
            cmd[2].dtyp = dt_word
        elif (op_m6_sl26_sr26 == 0x4):
            cmd.itype = self.inames['l.bf']
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + 4*SIGNEXT(op_m26_sl0_sr0, 26)
            cmd[0].dtyp = dt_word
        elif (op_m6_sl26_sr26 == 0x3):
            cmd.itype = self.inames['l.bnf']
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + 4*SIGNEXT(op_m26_sl0_sr0, 26)
            cmd[0].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xe) and (op_m2_sl8_sr8 == 0x0) and (op_m6_sl26_sr26 == 0x38):
            cmd.itype = self.inames['l.cmov']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m32_sl0_sr0 == 0x23000000):
            cmd.itype = self.inames['l.csyn']
        elif (op_m6_sl26_sr26 == 0x1c):
            cmd.itype = self.inames['l.cust']
        elif (op_m6_sl26_sr26 == 0x1d):
            cmd.itype = self.inames['l.cust']
        elif (op_m6_sl26_sr26 == 0x1e):
            cmd.itype = self.inames['l.cust']
        elif (op_m6_sl26_sr26 == 0x1f):
            cmd.itype = self.inames['l.cust']
        elif (op_m6_sl26_sr26 == 0x3c):
            cmd.itype = self.inames['l.cust5']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
            cmd[3].type = o_imm
            cmd[3].value = op_m6_sl5_sr5
            cmd[3].dtyp = dt_word
            cmd[4].type = o_imm
            cmd[4].value = op_m5_sl0_sr0
            cmd[4].dtyp = dt_word
        elif (op_m6_sl26_sr26 == 0x3d):
            cmd.itype = self.inames['l.cust']
        elif (op_m6_sl26_sr26 == 0x3e):
            cmd.itype = self.inames['l.cust']
        elif (op_m6_sl26_sr26 == 0x3f):
            cmd.itype = self.inames['l.cust']
        elif (op_m4_sl0_sr0 == 0x9) and (op_m2_sl8_sr8 == 0x3) and (op_m6_sl26_sr26 == 0x38):
            cmd.itype = self.inames['l.div']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xa) and (op_m2_sl8_sr8 == 0x3) and (op_m6_sl26_sr26 == 0x38):
            cmd.itype = self.inames['l.divu']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xc) and (op_m4_sl6_sr6 == 0x1) and (op_m6_sl26_sr26 == 0x38):
            cmd.itype = self.inames['l.extbs']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xc) and (op_m4_sl6_sr6 == 0x3) and (op_m6_sl26_sr26 == 0x38):
            cmd.itype = self.inames['l.extbz']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xc) and (op_m4_sl6_sr6 == 0x0) and (op_m6_sl26_sr26 == 0x38):
            cmd.itype = self.inames['l.exths']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xc) and (op_m4_sl6_sr6 == 0x2) and (op_m6_sl26_sr26 == 0x38):
            cmd.itype = self.inames['l.exthz']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xd) and (op_m4_sl6_sr6 == 0x0) and (op_m6_sl26_sr26 == 0x38):
            cmd.itype = self.inames['l.extws']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xd) and (op_m4_sl6_sr6 == 0x1) and (op_m6_sl26_sr26 == 0x38):
            cmd.itype = self.inames['l.extwz']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m2_sl8_sr8 == 0x0) and (op_m6_sl26_sr26 == 0x38):
            cmd.itype = self.inames['l.ff1']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xf) and (op_m2_sl8_sr8 == 0x1) and (op_m6_sl26_sr26 == 0x38):
            cmd.itype = self.inames['l.fl1']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
        elif (op_m6_sl26_sr26 == 0x0):
            cmd.itype = self.inames['l.j']
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + 4*SIGNEXT(op_m26_sl0_sr0, 26)
            cmd[0].dtyp = dt_word
        elif (op_m6_sl26_sr26 == 0x1):
            cmd.itype = self.inames['l.jal']
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + 4*SIGNEXT(op_m26_sl0_sr0, 26)
            cmd[0].dtyp = dt_word
        elif (op_m6_sl26_sr26 == 0x12):
            cmd.itype = self.inames['l.jalr']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl11_sr11
            cmd[0].dtyp = dt_word
        elif (op_m6_sl26_sr26 == 0x11):
            cmd.itype = self.inames['l.jr']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl11_sr11
            cmd[0].dtyp = dt_word
        elif (op_m6_sl26_sr26 == 0x24):
            cmd.itype = self.inames['l.lbs']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_displ
            cmd[1].addr = SIGNEXT(op_m16_sl0_sr0, 16)
            cmd[1].reg = op_m5_sl16_sr16
        elif (op_m6_sl26_sr26 == 0x23):
            cmd.itype = self.inames['l.lbz']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_displ
            cmd[1].addr = SIGNEXT(op_m16_sl0_sr0, 16)
            cmd[1].reg = op_m5_sl16_sr16
        elif (op_m6_sl26_sr26 == 0x20):
            cmd.itype = self.inames['l.ld']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_displ
            cmd[1].addr = SIGNEXT(op_m16_sl0_sr0, 16)
            cmd[1].reg = op_m5_sl16_sr16
        elif (op_m6_sl26_sr26 == 0x26):
            cmd.itype = self.inames['l.lhs']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_displ
            cmd[1].addr = SIGNEXT(op_m16_sl0_sr0, 16)
            cmd[1].reg = op_m5_sl16_sr16
        elif (op_m6_sl26_sr26 == 0x25):
            cmd.itype = self.inames['l.lhz']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_displ
            cmd[1].addr = SIGNEXT(op_m16_sl0_sr0, 16)
            cmd[1].reg = op_m5_sl16_sr16
        elif (op_m6_sl26_sr26 == 0x1b):
            cmd.itype = self.inames['l.lwa']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_displ
            cmd[1].addr = SIGNEXT(op_m16_sl0_sr0, 16)
            cmd[1].reg = op_m5_sl16_sr16
        elif (op_m6_sl26_sr26 == 0x22):
            cmd.itype = self.inames['l.lws']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_displ
            cmd[1].addr = SIGNEXT(op_m16_sl0_sr0, 16)
            cmd[1].reg = op_m5_sl16_sr16
        elif (op_m6_sl26_sr26 == 0x21):
            cmd.itype = self.inames['l.lwz']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_displ
            cmd[1].addr = SIGNEXT(op_m16_sl0_sr0, 16)
            cmd[1].reg = op_m5_sl16_sr16
        elif (op_m4_sl0_sr0 == 0x1) and (op_m6_sl26_sr26 == 0x31):
            cmd.itype = self.inames['l.mac']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl11_sr11
            cmd[1].dtyp = dt_word
        elif (op_m6_sl26_sr26 == 0x13):
            cmd.itype = self.inames['l.maci']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_imm
            cmd[1].value = SIGNEXT(op_m16_sl0_sr0, 16)
            cmd[1].dtyp = dt_word
        elif (op_m17_sl0_sr0 == 0x10000) and (op_m6_sl26_sr26 == 0x6):
            cmd.itype = self.inames['l.macrc']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0x3) and (op_m6_sl26_sr26 == 0x31):
            cmd.itype = self.inames['l.macu']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl11_sr11
            cmd[1].dtyp = dt_word
        elif (op_m6_sl26_sr26 == 0x2d):
            cmd.itype = self.inames['l.mfspr']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_imm
            cmd[2].value = op_m16_sl0_sr0
            cmd[2].dtyp = dt_word
        elif (op_m1_sl16_sr16 == 0x0) and (op_m6_sl26_sr26 == 0x6):
            cmd.itype = self.inames['l.movhi']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_imm
            cmd[1].value = op_m16_sl0_sr0
            cmd[1].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0x2) and (op_m6_sl26_sr26 == 0x31):
            cmd.itype = self.inames['l.msb']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl11_sr11
            cmd[1].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0x4) and (op_m6_sl26_sr26 == 0x31):
            cmd.itype = self.inames['l.msbu']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl11_sr11
            cmd[1].dtyp = dt_word
        elif (op_m32_sl0_sr0 == 0x22000000):
            cmd.itype = self.inames['l.msyn']
        elif (op_m6_sl26_sr26 == 0x30):
            cmd.itype = self.inames['l.mtspr']
            cmd[0].type = o_imm
            cmd[0].value = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
            cmd[3].type = o_imm
            cmd[3].value = op_m11_sl0_sr0
            cmd[3].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0x6) and (op_m2_sl8_sr8 == 0x3) and (op_m6_sl26_sr26 == 0x38):
            cmd.itype = self.inames['l.mul']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0x7) and (op_m2_sl8_sr8 == 0x3) and (op_m6_sl26_sr26 == 0x38):
            cmd.itype = self.inames['l.muld']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl11_sr11
            cmd[1].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xc) and (op_m2_sl8_sr8 == 0x3) and (op_m6_sl26_sr26 == 0x38):
            cmd.itype = self.inames['l.muldu']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl11_sr11
            cmd[1].dtyp = dt_word
        elif (op_m6_sl26_sr26 == 0x2c):
            cmd.itype = self.inames['l.muli']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_imm
            cmd[2].value = SIGNEXT(op_m16_sl0_sr0, 16)
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0xb) and (op_m2_sl8_sr8 == 0x3) and (op_m6_sl26_sr26 == 0x38):
            cmd.itype = self.inames['l.mulu']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl24_sr24 == 0x15):
            cmd.itype = self.inames['l.nop']
            cmd[0].type = o_imm
            cmd[0].value = op_m16_sl0_sr0
            cmd[0].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0x4) and (op_m2_sl8_sr8 == 0x0) and (op_m6_sl26_sr26 == 0x38):
            cmd.itype = self.inames['l.or']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m6_sl26_sr26 == 0x2a):
            cmd.itype = self.inames['l.ori']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_imm
            cmd[2].value = op_m16_sl0_sr0
            cmd[2].dtyp = dt_word
        elif (op_m32_sl0_sr0 == 0x22800000):
            cmd.itype = self.inames['l.psyn']
        elif (op_m6_sl26_sr26 == 0x9):
            cmd.itype = self.inames['l.rf']
        elif (op_m4_sl0_sr0 == 0x8) and (op_m4_sl6_sr6 == 0x3) and (op_m6_sl26_sr26 == 0x38):
            cmd.itype = self.inames['l.ror']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m2_sl6_sr6 == 0x3) and (op_m6_sl26_sr26 == 0x2e):
            cmd.itype = self.inames['l.rori']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_imm
            cmd[2].value = op_m6_sl0_sr0
            cmd[2].dtyp = dt_word
        elif (op_m6_sl26_sr26 == 0x36):
            cmd.itype = self.inames['l.sb']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl11_sr11
            cmd[0].dtyp = dt_word
            cmd[1].type = o_displ
            cmd[1].addr = SIGNEXT(op_m11_sl0_sr0 | op_m5_sl21_sr10, 16)
            cmd[1].reg = op_m5_sl16_sr16
        elif (op_m6_sl26_sr26 == 0x34):
            cmd.itype = self.inames['l.sd']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl11_sr11
            cmd[0].dtyp = dt_word
            cmd[1].type = o_displ
            cmd[1].addr = SIGNEXT(op_m11_sl0_sr0 | op_m5_sl21_sr10, 16)
            cmd[1].reg = op_m5_sl16_sr16
        elif (op_m11_sl21_sr21 == 0x720):
            cmd.itype = self.inames['l.sfeq']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl11_sr11
            cmd[1].dtyp = dt_word
        elif (op_m11_sl21_sr21 == 0x5e0):
            cmd.itype = self.inames['l.sfeqi']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_imm
            cmd[1].value = SIGNEXT(op_m16_sl0_sr0, 16)
            cmd[1].dtyp = dt_word
        elif (op_m11_sl21_sr21 == 0x72b):
            cmd.itype = self.inames['l.sfges']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl11_sr11
            cmd[1].dtyp = dt_word
        elif (op_m11_sl21_sr21 == 0x5eb):
            cmd.itype = self.inames['l.sfgesi']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_imm
            cmd[1].value = SIGNEXT(op_m16_sl0_sr0, 16)
            cmd[1].dtyp = dt_word
        elif (op_m11_sl21_sr21 == 0x723):
            cmd.itype = self.inames['l.sfgeu']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl11_sr11
            cmd[1].dtyp = dt_word
        elif (op_m11_sl21_sr21 == 0x5e3):
            cmd.itype = self.inames['l.sfgeui']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_imm
            cmd[1].value = SIGNEXT(op_m16_sl0_sr0, 16)
            cmd[1].dtyp = dt_word
        elif (op_m11_sl21_sr21 == 0x72a):
            cmd.itype = self.inames['l.sfgts']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl11_sr11
            cmd[1].dtyp = dt_word
        elif (op_m11_sl21_sr21 == 0x5ea):
            cmd.itype = self.inames['l.sfgtsi']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_imm
            cmd[1].value = SIGNEXT(op_m16_sl0_sr0, 16)
            cmd[1].dtyp = dt_word
        elif (op_m11_sl21_sr21 == 0x722):
            cmd.itype = self.inames['l.sfgtu']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl11_sr11
            cmd[1].dtyp = dt_word
        elif (op_m11_sl21_sr21 == 0x5e2):
            cmd.itype = self.inames['l.sfgtui']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_imm
            cmd[1].value = SIGNEXT(op_m16_sl0_sr0, 16)
            cmd[1].dtyp = dt_word
        elif (op_m11_sl21_sr21 == 0x5ed):
            cmd.itype = self.inames['l.sflesi']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_imm
            cmd[1].value = SIGNEXT(op_m16_sl0_sr0, 16)
            cmd[1].dtyp = dt_word
        elif (op_m11_sl21_sr21 == 0x725):
            cmd.itype = self.inames['l.sfleu']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl11_sr11
            cmd[1].dtyp = dt_word
        elif (op_m11_sl21_sr21 == 0x5e5):
            cmd.itype = self.inames['l.sfleui']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_imm
            cmd[1].value = SIGNEXT(op_m16_sl0_sr0, 16)
            cmd[1].dtyp = dt_word
        elif (op_m11_sl21_sr21 == 0x72c):
            cmd.itype = self.inames['l.sflts']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl11_sr11
            cmd[1].dtyp = dt_word
        elif (op_m11_sl21_sr21 == 0x5ec):
            cmd.itype = self.inames['l.sfltsi']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_imm
            cmd[1].value = SIGNEXT(op_m16_sl0_sr0, 16)
            cmd[1].dtyp = dt_word
        elif (op_m11_sl21_sr21 == 0x724):
            cmd.itype = self.inames['l.sfltu']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl11_sr11
            cmd[1].dtyp = dt_word
        elif (op_m11_sl21_sr21 == 0x5e4):
            cmd.itype = self.inames['l.sfltui']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_imm
            cmd[1].value = SIGNEXT(op_m16_sl0_sr0, 16)
            cmd[1].dtyp = dt_word
        elif (op_m11_sl21_sr21 == 0x721):
            cmd.itype = self.inames['l.sfne']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl11_sr11
            cmd[1].dtyp = dt_word
        elif (op_m11_sl21_sr21 == 0x5e1):
            cmd.itype = self.inames['l.sfnei']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_imm
            cmd[1].value = SIGNEXT(op_m16_sl0_sr0, 16)
            cmd[1].dtyp = dt_word
        elif (op_m6_sl26_sr26 == 0x37):
            cmd.itype = self.inames['l.sh']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl11_sr11
            cmd[0].dtyp = dt_word
            cmd[1].type = o_displ
            cmd[1].addr = SIGNEXT(op_m11_sl0_sr0 | op_m5_sl21_sr10, 16)
            cmd[1].reg = op_m5_sl16_sr16
        elif (op_m4_sl0_sr0 == 0x8) and (op_m4_sl6_sr6 == 0x0) and (op_m6_sl26_sr26 == 0x38):
            cmd.itype = self.inames['l.sll']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m2_sl6_sr6 == 0x0) and (op_m6_sl26_sr26 == 0x2e):
            cmd.itype = self.inames['l.slli']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_imm
            cmd[2].value = op_m6_sl0_sr0
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0x8) and (op_m4_sl6_sr6 == 0x2) and (op_m6_sl26_sr26 == 0x38):
            cmd.itype = self.inames['l.sra']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m2_sl6_sr6 == 0x2) and (op_m6_sl26_sr26 == 0x2e):
            cmd.itype = self.inames['l.srai']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_imm
            cmd[2].value = op_m6_sl0_sr0
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0x8) and (op_m4_sl6_sr6 == 0x1) and (op_m6_sl26_sr26 == 0x38):
            cmd.itype = self.inames['l.srl']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m2_sl6_sr6 == 0x1) and (op_m6_sl26_sr26 == 0x2e):
            cmd.itype = self.inames['l.srli']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_imm
            cmd[2].value = op_m6_sl0_sr0
            cmd[2].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0x2) and (op_m2_sl8_sr8 == 0x0) and (op_m6_sl26_sr26 == 0x38):
            cmd.itype = self.inames['l.sub']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m6_sl26_sr26 == 0x35):
            cmd.itype = self.inames['l.sw']
            cmd[0].type = o_displ
            cmd[0].addr = SIGNEXT(op_m11_sl0_sr0 | op_m5_sl21_sr10, 16)
            cmd[0].reg = op_m5_sl16_sr16
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl11_sr11
            cmd[1].dtyp = dt_word
        elif (op_m6_sl26_sr26 == 0x33):
            cmd.itype = self.inames['l.swa']
            cmd[0].type = o_displ
            cmd[0].addr = SIGNEXT(op_m11_sl0_sr0 | op_m5_sl21_sr10, 16)
            cmd[0].reg = op_m5_sl16_sr16
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl11_sr11
            cmd[1].dtyp = dt_word
        elif (op_m16_sl16_sr16 == 0x2000):
            cmd.itype = self.inames['l.sys']
            cmd[0].type = o_imm
            cmd[0].value = op_m16_sl0_sr0
            cmd[0].dtyp = dt_word
        elif (op_m16_sl16_sr16 == 0x2100):
            cmd.itype = self.inames['l.trap']
            cmd[0].type = o_imm
            cmd[0].value = op_m16_sl0_sr0
            cmd[0].dtyp = dt_word
        elif (op_m4_sl0_sr0 == 0x5) and (op_m2_sl8_sr8 == 0x0) and (op_m6_sl26_sr26 == 0x38):
            cmd.itype = self.inames['l.xor']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m6_sl26_sr26 == 0x2b):
            cmd.itype = self.inames['l.xori']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_imm
            cmd[2].value = SIGNEXT(op_m16_sl0_sr0, 16)
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x10) and (op_m6_sl26_sr26 == 0x32):
            cmd.itype = self.inames['lf.add.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x0) and (op_m6_sl26_sr26 == 0x32):
            cmd.itype = self.inames['lf.add.s']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m4_sl4_sr4 == 0xe) and (op_m6_sl26_sr26 == 0x32):
            cmd.itype = self.inames['lf.cust1.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl11_sr11
            cmd[1].dtyp = dt_word
        elif (op_m4_sl4_sr4 == 0xd) and (op_m6_sl26_sr26 == 0x32):
            cmd.itype = self.inames['lf.cust1.s']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl11_sr11
            cmd[1].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x13) and (op_m6_sl26_sr26 == 0x32):
            cmd.itype = self.inames['lf.div.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x3) and (op_m6_sl26_sr26 == 0x32):
            cmd.itype = self.inames['lf.div.s']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x15) and (op_m5_sl11_sr11 == 0x0) and (op_m6_sl26_sr26 == 0x32):
            cmd.itype = self.inames['lf.ftoi.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x5) and (op_m5_sl11_sr11 == 0x0) and (op_m6_sl26_sr26 == 0x32):
            cmd.itype = self.inames['lf.ftoi.s']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x14) and (op_m5_sl11_sr11 == 0x0) and (op_m6_sl26_sr26 == 0x32):
            cmd.itype = self.inames['lf.itof.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x4) and (op_m5_sl11_sr11 == 0x0) and (op_m6_sl26_sr26 == 0x32):
            cmd.itype = self.inames['lf.itof.s']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x17) and (op_m6_sl26_sr26 == 0x32):
            cmd.itype = self.inames['lf.madd.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x7) and (op_m6_sl26_sr26 == 0x32):
            cmd.itype = self.inames['lf.madd.s']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x12) and (op_m6_sl26_sr26 == 0x32):
            cmd.itype = self.inames['lf.mul.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x2) and (op_m6_sl26_sr26 == 0x32):
            cmd.itype = self.inames['lf.mul.s']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x16) and (op_m6_sl26_sr26 == 0x32):
            cmd.itype = self.inames['lf.rem.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x6) and (op_m6_sl26_sr26 == 0x32):
            cmd.itype = self.inames['lf.rem.s']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x18) and (op_m6_sl26_sr26 == 0x32):
            cmd.itype = self.inames['lf.sfeq.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl11_sr11
            cmd[1].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x8) and (op_m6_sl26_sr26 == 0x32):
            cmd.itype = self.inames['lf.sfeq.s']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl11_sr11
            cmd[1].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x1b) and (op_m6_sl26_sr26 == 0x32):
            cmd.itype = self.inames['lf.sfge.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl11_sr11
            cmd[1].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0xb) and (op_m6_sl26_sr26 == 0x32):
            cmd.itype = self.inames['lf.sfge.s']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl11_sr11
            cmd[1].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x1a) and (op_m6_sl26_sr26 == 0x32):
            cmd.itype = self.inames['lf.sfgt.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl11_sr11
            cmd[1].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0xa) and (op_m6_sl26_sr26 == 0x32):
            cmd.itype = self.inames['lf.sfgt.s']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl11_sr11
            cmd[1].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x1d) and (op_m6_sl26_sr26 == 0x32):
            cmd.itype = self.inames['lf.sfle.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl11_sr11
            cmd[1].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0xd) and (op_m6_sl26_sr26 == 0x32):
            cmd.itype = self.inames['lf.sfle.s']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl11_sr11
            cmd[1].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x1c) and (op_m6_sl26_sr26 == 0x32):
            cmd.itype = self.inames['lf.sflt.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl11_sr11
            cmd[1].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0xc) and (op_m6_sl26_sr26 == 0x32):
            cmd.itype = self.inames['lf.sflt.s']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl11_sr11
            cmd[1].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x19) and (op_m6_sl26_sr26 == 0x32):
            cmd.itype = self.inames['lf.sfne.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl11_sr11
            cmd[1].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x9) and (op_m6_sl26_sr26 == 0x32):
            cmd.itype = self.inames['lf.sfne.s']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl16_sr16
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl11_sr11
            cmd[1].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x11) and (op_m6_sl26_sr26 == 0x32):
            cmd.itype = self.inames['lf.sub.d']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x1) and (op_m6_sl26_sr26 == 0x32):
            cmd.itype = self.inames['lf.sub.s']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x30) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.add.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x31) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.add.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x32) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.adds.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x33) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.adds.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x34) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.addu.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x35) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.addu.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x36) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.addus.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x37) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.addus.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x10) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.all_eq.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x11) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.all_eq.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x12) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.all_ge.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x13) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.all_ge.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x14) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.all_gt.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x15) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.all_gt.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x16) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.all_le.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x17) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.all_le.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x18) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.all_lt.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x19) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.all_lt.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x1a) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.all_ne.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x1b) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.all_ne.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x38) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.and']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x20) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.any_eq.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x21) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.any_eq.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x22) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.any_ge.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x23) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.any_ge.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x24) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.any_gt.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x25) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.any_gt.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x26) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.any_le.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x27) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.any_le.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x28) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.any_lt.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x29) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.any_lt.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x2a) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.any_ne.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x2b) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.any_ne.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x39) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.avg.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x3a) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.avg.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x40) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.cmp_eq.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x41) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.cmp_eq.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x42) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.cmp_ge.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x43) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.cmp_ge.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x44) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.cmp_gt.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x45) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.cmp_gt.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x46) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.cmp_le.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x47) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.cmp_le.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x48) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.cmp_lt.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x49) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.cmp_lt.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x4a) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.cmp_ne.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x4b) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.cmp_ne.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m4_sl4_sr4 == 0xc) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.cust']
        elif (op_m4_sl4_sr4 == 0xd) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.cust']
        elif (op_m4_sl4_sr4 == 0xe) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.cust']
        elif (op_m4_sl4_sr4 == 0xf) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.cust']
        elif (op_m8_sl0_sr0 == 0x54) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.madds.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x55) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.max.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x56) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.max.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x57) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.merge.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x58) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.merge.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x59) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.min.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x5a) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.min.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x5b) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.msubs.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x5c) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.muls.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x5d) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.nand']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x5e) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.nor']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x5f) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.or']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x60) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.pack.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x61) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.pack.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x62) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.packs.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x63) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.packs.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x64) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.packus.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x65) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.packus.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x66) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.perm.n']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x67) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.rl.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x68) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.rl.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x6b) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.sll']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x69) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.sll.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x6a) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.sll.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x6e) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.sra.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x6f) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.sra.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x70) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.srl']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x6c) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.srl.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x6d) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.srl.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x71) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.sub.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x72) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.sub.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x74) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.subs.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x75) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.subu.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x76) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.subu.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x77) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.subus.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x78) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.subus.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x79) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.unpack.b']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x7a) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.unpack.h']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        elif (op_m8_sl0_sr0 == 0x7b) and (op_m6_sl26_sr26 == 0xa):
            cmd.itype = self.inames['lv.xor']
            cmd[0].type = o_reg
            cmd[0].reg = op_m5_sl21_sr21
            cmd[0].dtyp = dt_word
            cmd[1].type = o_reg
            cmd[1].reg = op_m5_sl16_sr16
            cmd[1].dtyp = dt_word
            cmd[2].type = o_reg
            cmd[2].reg = op_m5_sl11_sr11
            cmd[2].dtyp = dt_word
        return cmd.size

    def ana(self):
        try:
            return self._ana()
        except DecodingError:
            return 0

    def _emu_operand(self, op):
        if op.type == o_mem:
            ua_dodata2(0, op.addr, op.dtyp)
            ua_add_dref(0, op.addr, dr_R)
        elif op.type == o_near:
            if self.cmd.get_canon_feature() & CF_CALL:
                fl = fl_CN
            else:
                fl = fl_JN
            ua_add_cref(0, op.addr, fl)


    def emu(self):
        cmd = self.cmd
        ft = cmd.get_canon_feature()
        if ft & CF_USE1:
            self._emu_operand(cmd[0])
        if ft & CF_USE2:
            self._emu_operand(cmd[1])
        if ft & CF_USE3:
            self._emu_operand(cmd[2])
        if ft & CF_USE4:
            self._emu_operand(cmd[3])
        if not ft & CF_STOP:
            ua_add_cref(0, cmd.ea + cmd.size, fl_F)
        return True

    def outop(self, op):

        optype = op.type
        fl     = op.specval

        if optype == o_reg:
            out_register(self.regNames[op.reg])

        elif optype == o_imm:
            OutValue(op, OOFW_IMM | OOF_SIGNED)

        elif optype in [o_near, o_mem]:
            if optype == o_mem and fl == FL_ABSOLUTE:
                out_symbol('&')
            r = out_name_expr(op, op.addr, BADADDR)
            if not r:
                out_tagon(COLOR_ERROR)
                OutLong(op.addr, 16)
                out_tagoff(COLOR_ERROR)
                QueueSet(Q_noName, self.cmd.ea)

        elif optype == o_displ:
            # 16-bit index is signed
            OutValue(op, OOF_ADDR | OOFW_8 | OOF_SIGNED)
            out_symbol('(')
            out_register(self.regNames[op.reg])
            out_symbol(')')

        elif optype == o_phrase:
            out_symbol('@')
            out_register(self.regNames[op.reg])
        else:
            return False

        return True

    def out(self):
        cmd = self.cmd
        ft = cmd.get_canon_feature()
        buf = init_output_buffer(1024)
        OutMnem(15)
        if ft & CF_USE1:
            out_one_operand(0)
        if ft & CF_USE2:
            OutChar(',')
            OutChar(' ')
            out_one_operand(1)
        if ft & CF_USE3:
            OutChar(',')
            OutChar(' ')
            out_one_operand(2)
        term_output_buffer()
        cvar.gl_comm = 1
        MakeLine(buf)

def PROCESSOR_ENTRY():
    return openrisc_processor_t()

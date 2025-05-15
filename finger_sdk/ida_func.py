import idc
import idaapi
import ida_ida
import idautils
import re


class FuncSigFeature:
    def __init__(self):
        self.file_path = idc.get_input_file_path()
        self.code_list = ["", ".text", ".plt", ".got", "extern", ".pdata", ".bss"]
        self.control_ins_list = [
            "call","jc","jnc","jz","jnz","js","jns","jo","jno","jp",
            "jpe","jnp","jpo","ja","jnbe","jae","jnb","jb","jnae","jbe",
            "jna","je","jne","jg","jnle","jge","jnl","jl","jnge","jle","jng"
        ]
        self.string_list = { str(s): s.ea for s in idautils.Strings() }

    def get_file_structure(self):
        # IDA9+ 统一用 ida_ida 接口
        proc = ida_ida.inf_get_procname()           # 处理器名称
        if ida_ida.inf_is_be():                     # 大端/小端
            endian = "MSB"
        else:
            endian = "LSB"
        return proc, endian

    def get_file_type(self):
        # 位宽
        if ida_ida.inf_is_64bit():
            fmt = "64"
        elif ida_ida.inf_is_32bit():
            fmt = "32"
        else:
            fmt = "16"
        # 格式
        ft = idaapi.get_file_type_name()
        # 或者用 idaapi.get_inf_structure().filetype 对比 idaapi.f_PE/ELF
        # 但 get_file_type_name 返回类似 "PE" 或 "ELF"
        return fmt, ft

    def get_module_info(self):
        return idc.ARGV[1] if len(idc.ARGV) == 2 else ""

    def byte2str(self, b):
        return b.decode() if isinstance(b, (bytes, bytearray)) else b

    def extract_const(self, ea):
        mnem = idc.print_insn_mnem(ea)
        if mnem in self.control_ins_list:
            return ""
        for op in (0,1):
            t = idc.get_operand_type(ea, op)
            if t == idc.o_mem:
                addr = idc.get_operand_value(ea, op)
                if idc.get_segm_name(addr) not in self.code_list:
                    raw = idc.get_strlit_contents(addr)
                    if raw:
                        s = self.byte2str(raw)
                        if s in self.string_list and addr == self.string_list[s]:
                            return s
        return ""

    def get_ins_feature(self, start):
        ins_bytes, ins_strs = [], []
        for ea in idautils.FuncItems(start):
            ins_bytes.append(idc.get_bytes(ea, idc.get_item_size(ea)))
            ins_strs.append(self.extract_const(ea))
        return ins_bytes, ins_strs

    def filter_segment(self, ea):
        return idc.get_segm_name(ea) in ("extern", ".plt", ".got", ".idata")


def get_func_feature(ea):
    f = idaapi.get_func(ea)
    if not f:
        return None
    start = f.start_ea
    F = FuncSigFeature()
    if F.filter_segment(start):
        return None

    proc, endian = F.get_file_structure()
    fmt, ftype = F.get_file_type()
    module = F.get_module_info()
    ins_bytes, ins_strs = F.get_ins_feature(start)

    return {
        "extmsg":   [proc, endian, fmt, ftype, module],
        "ins_bytes": ins_bytes,
        "ins_str":   ins_strs,
        "func_name": idaapi.get_func_name(start),
    }

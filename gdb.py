import binaryninja
import gdb,sys

if '':
    sys.path.append("/home/ex/coding/phalanx/")
    from gef import GenericCommand, register, only_if_gdb_running, gef 

# bv = binaryninja.open_view("a.bndb", options={'analysis.limits.maxFunctionSize':0})
bv = binaryninja.open_view("new.bndb")
addr = 0x1178
curr_func = bv.get_functions_containing(addr)[0]



@register
class GetStackVars(GenericCommand):
    """Dumps Stack Varibles"""
    _cmdline_ = "gsv"
    _syntax_  = f"{_cmdline_}"

    @only_if_gdb_running
    def get_base(self) -> int:
        vmmap = gef.memory.maps 
        base_address = [x.page_start for x in vmmap if x.path == get_filepath()][0]
        return base_address

    @only_if_gdb_running
    def do_invoke(self, argv):
        addr = gef.arch.pc - self.get_base()
        curr_func = bv.get_functions_containing(addr)[0]
        for stk_var in curr_func.vars:
            # storage already neg
            var_addr = gef.arch.register('rbp') + 8 + stk_var.storage
            print(f"{stk_var.name}-> {hex(var_addr)}\n\t{hex(gef.memory.read_integer(var_addr))}")
            gdb.set_convenience_variable(stk_var.name, gef.memory.read_integer(var_addr))
        return

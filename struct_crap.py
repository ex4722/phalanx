import binaryninja

bv = binaryninja.open_view("new.bndb")
addr = 0x1178
curr_func = bv.get_functions_containing(addr)[0]
dyn = bv.types["Elf64_Dyn"]
s = bv.types["struct_2"]


def member_at_offset(structure : binaryninja.types.StructureType , offset: int):
    """ 
    member_at_offset(structure : binaryninja.types.StructureType , offset: int):
    
    Returns none instead of erroring when nothing found
    """
    try:
        return structure.member_at_offset(offset)
    except ValueError:
        return None


def patch_struct( structure : binaryninja.types.StructureType) -> binaryninja.types.StructureType:
    """
    patch_struct( structure : binaryninja.types.StructureType) -> binaryninja.types.StructureType:

    Returns a copy of structure that is padded with char[] for all non defined structures
    :param StructureType structure:
    """
    structure = structure.mutable_copy()
    i = 0
    times_padded = 1

    while i < structure.width:
        member = member_at_offset(structure, i)
        # Not defined, find how long undef chain is
        if member == None:
            null_c = 0
            while member_at_offset(structure,null_c + i) == None and (null_c + i ) < structure.width:
                null_c += 1
            structure.add_member_at_offset(f'BN_PADDING_{times_padded}', binaryninja.types.ArrayBuilder.create(binaryninja.types.CharType.create(), null_c ), i)
            i += null_c
            times_padded += 1

        else:
            i += member.type.width
    return structure.immutable_copy()


# bv = binaryninja.open_view("./chall")
# bv = binaryninja.open_view("chall.bndb")
a = 0


func_list = []

def get_source(typed : binaryninja.types.StructureType):
    """ 
    get_source(typed : binaryninja.types.StructureType):
    
    Returns a string with valid C code for the struct type
    """
    name = typed.tokens[-1]
    type_str = ""
    if isinstance(typed, binaryninja.types.NamedTypeReferenceType):
        type_str = str(typed.get_lines(bv,str(name))[0]) + '\n'

    elif isinstance(typed,binaryninja.types.StructureType):
        typed = patch_struct(typed)
        for x in typed.get_lines(bv,str(name)):
            # Check once? Too lazy :)
            type_str += str(x).split(":")[0] +"\n"    

    elif isinstance(typed,binaryninja.types.EnumerationType):
        for x in typed.get_lines(bv,str(name)):
            # Check once for packed? Too lazy :)
            type_str += str(x).split(":")[0] +"\n"    

    type_str = type_str.replace("__packed", "")
    return type_str

func_list = []


def resolve_structure(typed : binaryninja.types.StructureType):
    print(f"{typed.__str__()=}")
    global a
    match typed.type_class:
        case binaryninja.TypeClass.StructureTypeClass:
            dep = [member.type for member in typed.members]
            for i in dep:
                resolve_structure(i)
        case binaryninja.TypeClass.NamedTypeReferenceClass:
            resolve_structure(typed.target(bv))
        case binaryninja.TypeClass.EnumerationTypeClass:
            pass
        case _:
            print(typed)

    if typed in func_list:
        print("ALREADY IN")
    else:
        print(f"Resolved {typed}")
        func_list.append(typed)

for name, f in bv.types:
    resolve_structure(f)

def generate_source():
    # https://stackoverflow.com/questions/7272558/can-we-define-a-new-data-type-in-a-gdb-session
    source = ''
    source += '#include <stdio.h>\n#include <stdlib.h>\n#include <stdint.h>\n'
    for i in func_list:
        source += get_source(i)
    # source += 'int main (int argc, char *argv[]) { return 0; }'
    with open("/tmp/shogun_tmp.h",'w') as f:
        f.write(source)

    with open("/tmp/shogun_tmp.c",'w') as f:
        source = ''
        source += '#include <stdio.h>\n#include <stdlib.h>\n#include <stdint.h>\n'
        # Need to struct everything
        f.write(source)
    return source 

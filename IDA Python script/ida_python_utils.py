import idautils
import ida_bytes


def restring(start_addr, end_addr):
    curr_addr = start_addr
    print("started renaming strings.")
    while curr_addr < end_addr:
        ida_bytes.create_strlit(curr_addr, 0, ida_nalt.STRTYPE_TERMCHR)
        curr_addr += 4

    print("Finshed restring.")


def smart_restring(start_addr, end_addr, min_str_len=3):
    curr_addr = start_addr
    print("started smart renaming strings.")
    while curr_addr < end_addr:

        potential_len = ida_bytes.get_max_strlit_length(curr_addr, 0)
        if potential_len > min_str_len:
            ida_bytes.create_strlit(curr_addr, 0, ida_nalt.STRTYPE_TERMCHR)

        curr_addr += 1

    print("Finished smart renaimng strings")


def redefine_methods(start_addr, end_addr):
    curr_addr = start_addr
    print("started redefine methods.")
    while curr_addr < end_addr:
        if idc.get_func_name(curr_addr) == '':
            idc.add_func(curr_addr)

        curr_addr += 4

    print("Finshed redefine methods.")


def redefine_references(start_addr, end_addr):
    curr_addr = start_addr
    print("started redefine references.")
    while curr_addr < end_addr:
        ida_offset.op_offset(curr_addr, 0, idc.REF_OFF32)
        ida_offset.op_offset(curr_addr, 1, idc.REF_OFF32)
        ida_offset.op_offset(curr_addr, 2, idc.REF_OFF32)
        curr_addr += 4

    print("Finshed redefine references.")


def rename_methods_based_on_ref_table_v1(start_addr, end_addr):
    curr_addr = start_addr
    next_addr = curr_addr + 4
    while next_addr < end_addr:
        curr_addr_content = idc.Dword(curr_addr)
        curr_addr_string = idc.GetString(curr_addr_content + 2)  # NOTE: the +2 is for current firmware

        if curr_addr_string is None or curr_addr_string == '':
            curr_addr += 4
            next_addr += 4
            continue

        next_addr_content = idc.Dword(next_addr)
        next_addr_method_name = idc.GetFunctionName(next_addr_content)

        if next_addr_method_name is None or next_addr_method_name == '' or not next_addr_method_name.startswith("sub_"):
            curr_addr += 4
            next_addr += 4
            continue
        print("Renaming {src}->{dst} ".format(src=next_addr_method_name, dst=curr_addr_string))
        idc.MakeNameEx(next_addr_content, curr_addr_string, idc.SN_NOWARN)

        curr_addr += 4
        next_addr += 4


def rename_methods_based_on_ref_table_v2(start_addr, end_addr):
    curr_addr = start_addr
    next_addr = curr_addr + 4
    while next_addr < end_addr:
        curr_addr_content = ida_bytes.get_dword(curr_addr)
        print(curr_addr_content)
        curr_addr_string = str(ida_bytes.get_strlit_contents(curr_addr_content, -1,
                                                             STRTYPE_TERMCHR))  # NOTE: the +2 is for current firmware

        if curr_addr_string is None or curr_addr_string == '':
            curr_addr += 4
            next_addr += 4
            continue

        next_addr_content = ida_bytes.get_dword(next_addr)
        next_addr_method_name = idc.get_func_name(next_addr_content)

        if next_addr_method_name is None or next_addr_method_name == '' or not next_addr_method_name.startswith("sub_"):
            curr_addr += 4
            next_addr += 4
            continue

        print("Renaming {src}->{dst} ".format(src=next_addr_method_name, dst=curr_addr_string))
        idc.set_name(next_addr_content, curr_addr_string, idc.SN_NOWARN)

        curr_addr += 4
        next_addr += 4


def rename_methods_by_references(start_addr, end_addr):
    """
    NOTE: in case of number of segments you should use get_func_name instead of the string one
    NOTE: Tis good for 32 systems for 64 we should change get_dword to get_qword
    """
    current_address = start_addr
    next_address = current_address + 4

    while next_address < end_addr:

        current_address_content = ida_bytes.get_dword(current_address)
        new_name = ida_bytes.get_strlit_contents(current_address_content, -1, STRTYPE_TERMCHR)

        if new_name is None or new_name == '':
            current_address += 4
            next_address += 4
            continue

        next_address_content = ida_bytes.get_dword(next_address)
        old_name = idc.get_func_name(next_address_content)

        if old_name is not None and type(old_name) is not str:
            old_name = old_name.decode('ascii')

        if new_name is not None and type(new_name) is not str:
            new_name = new_name.decode('ascii')

        if old_name is None or ' ' in old_name:
            current_address += 4
            next_address += 4
            continue

        print(hex(current_address_content), new_name, old_name)

        print("Renaming {src}->{dst} ".format(src=old_name, dst=new_name))
        idc.set_name(next_address_content, str(new_name), 0x800)  # 0x800 SN_FORCE

        current_address += 4
        next_address += 4



def rename_methods_based_on_ref_for_codesys_emulator(start_addr, end_addr):
    """
    NOTE: in case of number of segments you should yuse get_func_name instead of the string one
    NOTE: this is for x64 for x32 do + 4
    :param start_addr:
    :param end_addr:
    :return:
    """

    curr_addr = start_addr
    next_addr = curr_addr
    next_addr = next_addr + 4
    while next_addr < end_addr:

        curr_addr_content = idc.get_wide_dword(curr_addr)
        old_name = str(ida_funcs.get_func_name(curr_addr_content))

        if old_name is None or old_name == '':
            curr_addr += 4
            next_addr += 4
            continue

        next_addr_content = idc.get_qword(next_addr)
        new_name = idc.get_strlit_contents(next_addr_content, -1, STRTYPE_TERMCHR)

        if new_name is None:
            curr_addr += 4
            next_addr += 4
            continue

        new_name = new_name.decode('ascii')

        if len(new_name) < 3:
            curr_addr += 4
            next_addr += 4
            continue

        print("Renaming {src}->{dst} ".format(src=old_name, dst=new_name))
        ret = idc.set_name(curr_addr_content, new_name, idc.SN_NOWARN)

        curr_addr += 4
        next_addr += 4



def find_all_refs(addr, arg_val=None, operand=0xE3):
    """
    Searches for x ref to given function address
    then for each xref gets last five opcodes
    and searches for 0x21 opcode which is the setting of R1
    checking the value if its 0x22
    then print the location
    """
    map = {}
    for xref in idautils.XrefsTo(addr):
        # print(xref.type, XrefTypeName(xref.type), 'from', hex(xref.frm), 'to', hex(xref.to))
        tar_addr = xref.frm

        for i in range(5):
            opcode = idc.GetManyBytes(PrevHead(tar_addr), ItemSize(PrevHead(tar_addr)))
            array_opcode = [int(ord(i)) for i in opcode]
            if array_opcode[len(array_opcode) - 1] == operand:  # LDR = 0xE5,mov = 0xE3
                if arg_val is None:
                    map[tar_addr] = array_opcode
                else:
                    if array_opcode[0] == arg_val:
                        map[tar_addr] = array_opcode
            tar_addr = PrevHead(tar_addr)

        # args = idaapi.get_arg_addrs(xref.frm)
        # print(xref.frm, args)

    return map


def rename_if_name_contains(start_addr, end_addr):
    curr_addr = start_addr
    while curr_addr < end_addr:
        curr_addr += 1


def create_sturct_with_fields(struct_name, amount_of_qdwords):
    id = add_struc(-1, struct_name, 0)
    for i in range(amount_of_qdwords):
        print("added field field_%x" % i + " to struct " + struct_name)
        add_struc_member(id, "field_%x" % i, i, FF_DATA | FF_QWORD, -1, 8)
    print("Finished adding structs")


def rename_based_on_inheritance_strings():
    """
    Rename methods that have those kind of strings: ipnet_nat_proxy_dns_parse_questions() :: could not add transaction to list
    """
    import idautils
    sc = idautils.Strings()
    for s in sc:
        if "::" in str(s):
            prev_address = s.ea - 4
            ref_to_prev_address = get_first_dref_to(prev_address)
            old_method_name = ida_funcs.get_func_name(ref_to_prev_address)

            if old_method_name is None:
                prev_address = s.ea - 8
                ref_to_prev_address = get_first_dref_to(prev_address)
                old_method_name = ida_funcs.get_func_name(ref_to_prev_address)
                if old_method_name is None:
                    continue

            parts = str(s).split("::")
            relevant_part = parts[0]
            new_method_name = relevant_part.replace("(", "").replace(")", "")

            if "%" in new_method_name:
                new_method_name = new_method_name.split("%")[0]
            if "~" in new_method_name:
                new_method_name = new_method_name.replace("~", "")
            if ":" in new_method_name:
                new_method_name = new_method_name.replace(":", "")

            if new_method_name is not None and old_method_name is not None and old_method_name.startswith("sub_"):
                old_method_address = get_name_ea(0, old_method_name)
                if old_method_address is not None:
                    print("Renaming {src}->{dst} ".format(src=old_method_name, dst=new_method_name))
                    idc.set_name(old_method_address, new_method_name, idc.SN_NOWARN)


def is_camel_case(s):
    return s != s.lower() and s != s.upper() and "_" not in s


def get_all_camel_case_words_in_image():
    """
    So the idea is that lets say we have a log that looks like
    ClassA::SendData() failed with error code %d ....
    and we have ref for this location we want to rename all the relevant methods
    with those names
    """
    print("Searching for all camel case worlds")
    import idautils
    sc = idautils.Strings()
    for s in sc:
        parts = str(s).split(" ")
        if 2 < len(parts) and is_camel_case(parts[0]) and parts[1] == "not":
            print(parts[0])


def rename_based_on_logs():
    """
    The idea is to rename methods that got strings that looks like:
    'ProcessEventRequestState(Device:%d) action %p max pending actions'
    or
    'ServerInit: invalid parameter'
    """
    import idautils
    sc = idautils.Strings()
    new_method_name = None
    for s in sc:
        s_as_str = str(s)
        prev_address = s.ea
        ref_to_prev_address = get_first_dref_to(prev_address)
        old_method_name = ida_funcs.get_func_name(ref_to_prev_address)
        old_method_address = get_name_ea(0, old_method_name)

        if "(" in s_as_str and ":" in s_as_str and s_as_str.find("c") < s_as_str.find(":"):
            parts = s_as_str.split(" ")
            name_with_extra_data = parts[0]
            name_parts = name_with_extra_data.split("(")
            parts[0] = parts[0].replace(":", "")
            new_method_name = name_parts[0] if len(name_parts[0]) > 4 else None

        elif ":" in s_as_str:
            parts = s_as_str.split(":")
            parts[0] = parts[0].replace(":", "")
            name_parts = parts[0].split(" ")

            if len(name_parts) > 1:
                continue
            new_method_name = parts[0] if len(parts[0]) > 4 else None

            if new_method_name is not None and new_method_name.startswith(" "):
                continue

        if new_method_name is not None and old_method_name is not None and old_method_name.startswith("sub_"):
            print("Renaming {src}->{dst} ".format(src=old_method_name, dst=new_method_name))
            ret_code = idc.set_name(old_method_address, new_method_name, idc.SN_NOWARN)

        new_method_name = None


def rename_based_on_particular_suffix(suffix_to_renamed_based_on, prefix):
    """
    Rename method based on specific suffix
    """
    import idautils
    sc = idautils.Strings()

    for s in sc:
        s_as_str = str(s)
        prev_address = s.ea
        ref_to_prev_address = get_first_dref_to(prev_address)
        old_method_name = ida_funcs.get_func_name(ref_to_prev_address)
        old_method_address = get_name_ea(0, old_method_name)

        if s_as_str.endswith(suffix_to_renamed_based_on) and old_method_name.startswith("sub"):
            s_as_str = s_as_str.replace(" ", "")
            new_method_name = "{prefix}{name}".format(prefix=prefix, name=s_as_str)
            print("Renaming {src}->{dst} ".format(src=old_method_name, dst=new_method_name))
            ret_code = idc.set_name(old_method_address, new_method_name, idc.SN_NOWARN)
            print("returned", ret_code)


def find_blx_gadgets():
    data = ""
    for function_ea in idautils.Functions():
        instructions = []

        for ins in idautils.FuncItems(function_ea):
            if idaapi.is_code(idaapi.get_full_flags(ins)):
                cmd = idc.GetDisasm(ins)
                instructions.append([cmd, ins])

        for i in range(len(instructions) - 5):
            print(instructions)
            if "BLX" in instructions[i + 4][0]:

                data += str(hex(instructions[i][1])) + \
                        "-> [" + "\n" + \
                        instructions[i][0] + "\n" + \
                        instructions[i + 1][0] + "\n" + \
                        instructions[i + 2][0] + "\n" + \
                        instructions[i + 3][0] + "\n" + \
                        instructions[i + 4][0] + "\n"

    with open(r"GadgetsWithBLX.txt", "w") as f:
        f.write(data)

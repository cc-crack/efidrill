class x64:
    arch_name = "x64"
    function_param = ["RCX","RDX","R8","R9"]
    register_list = ["RAX", #0
                     "RCX", #1
                     "RDX", #2
                     "RBX", #3
                     "RSP", #4
                     "RBP", #5
                     "RSI", #6
                     "RDI", #7
                     "R8",
                     "R9",
                     "R10",
                     "R11",
                     "R12",
                     "R13",
                     "R14"

                     ]
    call_name = 'call'
    xor_name = 'xor'
    mul_name = 'mul'
    sub_name = 'sub'
    cmp_name = 'cmp'
    and_name = 'and'
    stack_register = ['RSP',"RBP","R11"]
    bigger_jmp = ['ja','jnbe']
    small_jmp = ['jb',]

    equal_jmp = ['jz','je']
    unequal_jmp = ['jnz','jne']
    not_bigger_jmp = ['jbe','jna']
    not_small_jmp = ['jnb']
    lib_point_size = 0x8
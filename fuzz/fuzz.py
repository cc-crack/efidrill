import json
import random
import struct


def get_random_bytes():
    return random.randbytes()


def get_random_point():
    return struct.pack("Q<", ql.os.smm.smbase - random.randint() & 0x30)


def get_seed(fuzz_struct):
    for struct_dict in fuzz_struct:
        payload = b""
        if struct_dict["type_guess"] == "Point":
            for i in range(int(struct_dict["size"] / 8)):
                payload += get_random_point()
            ql.mem.write(0x7000 + struct_dict["offset"], payload)

        else:
            for i in range(struct_dict["size"]):
                payload += get_random_bytes()
            ql.mem.write(0x7000 + struct_dict["offset"], payload)


def fuzz_smi():
    pass


with open("struct.txt", "r") as f:
    struct_data_list = f.read().split("\n")
for struct_list_index in range(len(struct_data_list)):
    fuzz_struct = json.loads(struct_data_list[struct_list_index])
    for i in range(10):
        get_seed(fuzz_struct)
        fuzz_smi()

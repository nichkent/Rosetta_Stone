import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import pefile


def read_pe_code(file_path):
    """
    Reads the code section from a PE file.
    """
    try:
        pe = pefile.PE(file_path)
        for section in pe.sections:
            if section.Name.startswith(b'.text'):
                code = section.get_data()
                start_address = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
                return code, start_address
        print("Error: Code section not found.")
        sys.exit(1)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    except pefile.PEFormatError:
        print(f"Error: '{file_path}' is not a valid PE file.")
        sys.exit(1)


def disassemble_code(code, start_address, arch=CS_ARCH_X86, mode=CS_MODE_32):
    """
    Disassembles the given code starting from the specified address.
    """
    md = Cs(arch, mode)
    md.detail = True
    for instruction in md.disasm(code, start_address):
        print(f"0x{instruction.address:08x}:\t{instruction.mnemonic}\t{instruction.op_str}")


def main():
    if len(sys.argv) != 2:
        print("Usage: python simple_disassembler.py <pe_file>")
        sys.exit(1)

    file_path = sys.argv[1]
    code, start_address = read_pe_code(file_path)
    disassemble_code(code, start_address)


if __name__ == "__main__":
    main()

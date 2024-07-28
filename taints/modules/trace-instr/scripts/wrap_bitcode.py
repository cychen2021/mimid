# coding=utf-8

import sys
import os

wrapped_functions = {
    "@read" : "read",
    "@\"\\01_read\"": "read",
    "@fread" : "fread",
    "@\"\\01_fread\"": "fread",
    "@fscanf" : "fscanf",
    "@\"\\01_fscanf\"": "fscanf",
    "@gets": "gets",
    "@fgets": "fgets",
    "@fgetc": "fgetc",
    "@getc": "getc",
    "@ungetc": "ungetc",
    "@recv": "recv",
    "@\"\\01_recv\"": "recv",
    "@fork": "fork",
    "@pthread_create": "pthread_create",
    "@exit": "exit",
    "@close": "close",
    "@\"\\01_close\"": "close",
    "@fclose": "fclose",
    "@\"\\01_fclose\"": "fclose",
    "@open": "open",
    "@\"\\01_open\"": "open",
    "@dup": "dup",
    "@dup2": "dup2",
    "@vsnprintf": "vsnprintf",
    "@__vsnprintf_chk": "vsnprintf_chk",
    "@isdigit": "isdigit",
    "@islower": "islower",
    "@isupper": "isupper",
    "@isalpha": "isalpha",
    "@isxdigit": "isxdigit",
    "@isspace": "isspace",
    "@isprint": "isprint",
    "@isgraph": "isgraph",
    "@isblank": "isblank",
    "@iscntrl": "iscntrl",
    "@ispunct": "ispunct",
    "@isalnum": "isalnum",
    "@strtod": "strtod",
    "@\"\\01_strtod": "strtod",
    "@strtold": "strtold",
    "@\"\\01_strtold": "strtold",
    "@strtof": "strtof",
    "@\"\\01_strtof": "strtof",
    "@strtol": "strtol",
    "@\"\\01_strtol": "strtol",
    "@strtoll": "strtoll",
    "@\"\\01_strtoll": "strtoll",
    "@strtoull": "strtoul",
    "@\"\\01_strtoull": "strtoull",

    # cmimid functions
    # "@method__enter": "method__enter",
    # "@method__exit": "method__exit",
    # "@stack__enter": "stack__enter",
    # "@stack__exit": "stack__exit",
    # "@scope__enter": "scope__enter",
    # "@scope__exit": "scope__exit",
    # "@dup3": "dup3",
}


def main(inputfile):
    global wrapped_functions
    infile_split = os.path.split(inputfile)
    with open(inputfile, "r") as input, open(os.path.join(infile_split[0], f"{infile_split[1][:-3]}.wrapped.bc"), "w") as outfile:
        for line in input.readlines():
            printline = line
            for (key, val) in wrapped_functions.items():
                if key + "(" in line:
                    printline = line.replace(key + "(", f"@tracerllvm_wrap_{val}(")
                    print(printline)
                elif key + "," in line:
                    printline = line.replace(key + ",", f"@tracerllvm_wrap_{val},")
                    print(printline)
            outfile.write(printline)


if __name__ == "__main__":
    main(sys.argv[1])
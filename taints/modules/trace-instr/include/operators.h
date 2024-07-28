#ifndef TRACEINSTR_OPERATORS_H
#define TRACEINSTR_OPERATORS_H

enum OPCODE {
// the first free opcode by llvm definition
#define LAST_OTHER_INST(NUM) METHODENTRY = NUM + 1,
#include <llvm/IR/Instruction.def>

    FILEPOSITION,
    FSCANF,
    FGETS,
    FGETC,
    TRACERFREAD, //named TRACERFREAD because fcntl.h defines FREAD
    STRTO,
    REALLOC,
    ALLOC,
    STRDUP,
    STRNDUP,
    SSCANF,
    SPRINTF,
    READ,
    STRCMP,
    GETCHAR,
    BBENTER,
    STRCHR,
    GLOBPRINT,
    STRTOK,
    STRSTR,
    FDBINDING,
    VSNPRINTF,
    CMIMID,
    ISX,
    UNGETC
};

#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
//#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>

#include "callbacks.h"
#include "operators.h"

char* tracerllvm_wrap_fgets(char* restrict str, int size, FILE* restrict stream)
{
    tracerllvm_addInformation(FGETS);
    char* result;
    tracerllvm_optOpcode(FGETS);
    if ((result = fgets(str, size, stream)) != NULL)
    {
        tracerllvm_optInput(fileno(stream), result);
    }

    tracerllvm_instructionEnd();
    return result;
}

int tracerllvm_wrap_fgetc(FILE* stream)
{
    tracerllvm_addInformation(FGETC);
    int result;
    tracerllvm_optOpcode(FGETC);
    if ((result = fgetc(stream)) != EOF)
    {
        char str[2] = {(char)result, '\0'};
        tracerllvm_optInput(fileno(stream), str);
    }

    tracerllvm_instructionEnd();
    return result;
}

int tracerllvm_wrap_ungetc(int character, FILE* stream)
{
    tracerllvm_addInformation(UNGETC);
    int result;
    tracerllvm_optOpcode(UNGETC);
    if ((result = ungetc(character, stream)) != EOF)
    {
        char str[2] = {character, '\0'};
        tracerllvm_optInput(fileno(stream), str);
    }

    tracerllvm_instructionEnd();
    return result;
}

int tracerllvm_wrap_getc(FILE* stream)
{
    return tracerllvm_wrap_fgetc(stream);
}

int tracerllvm_wrap_read(int fd, void* buffer, size_t length)
{
    tracerllvm_addInformation(READ);
    int result;
    printf("Read new stuff.\n");
    tracerllvm_optOpcode(READ);
    if ((result = read(fd, buffer, length)) > 0)
    {
        if (length >= 13 && strncmp(buffer, "proFuzzer End", 13) == 0) {
            // we received the end command, the subject will be terminated
            tracerllvm_instructionEnd();
            tracerllvm_endTrace();
            close(fd);
            exit(0);
        }
        void* buf = calloc(1, result + 1);
        strncpy(buf, buffer, result);
        tracerllvm_optInput((uintptr_t)fd, buf);
        free(buf);
    }
    tracerllvm_instructionEnd();
    return result;
}

size_t tracerllvm_wrap_fread(void *ptr,size_t size, size_t count, FILE* stream)
{
    tracerllvm_addInformation(TRACERFREAD);
    int result;
    tracerllvm_optOpcode(TRACERFREAD);
    if ((result = fread(ptr, size, count, stream)) > 0)
    {
        void* buf = calloc(1, result + 1);
        strncpy(buf, ptr, result);
        tracerllvm_optInput(fileno(stream), buf);
        free(buf);
    }
    tracerllvm_instructionEnd();
    return result;
}

char* convertFormat(const char * format) {
    // TODO make this work, then use the converted format specifier to print the va_args one by one as void pointers
    char* newFormat = calloc(1, strlen(format) * sizeof(char*) * 2);
    int newFormatCounter = 0; // counter where to save a char in the newFormat string
    printf("Format String: %s\n", format);
    int inSpecifier = 0;
    int inRangeSpecifier = 0; // the %[.*] specifier
    for (int i = 0; i < strlen(format); i++) {
        if (format[i] == '%') {
            newFormat[newFormatCounter++] = '\31'; //TODO replace this with \31 later, this is just for debugging
            newFormat[newFormatCounter++] = '%';
            inSpecifier = 1;
            continue;
        }
        if (!inSpecifier) {
            newFormat[newFormatCounter++] = format[i];
            continue;
        }
        if (strchr("%iudoxfegacsp[]n", format[i]) != 0) {
            if (!inRangeSpecifier) {
                inSpecifier = 0;
            }
            if (!inRangeSpecifier && 'n' == format[i]) {
                // the result of reading %n is an integer, so replace with d
                newFormat[newFormatCounter++] = 'd';
            }else if (!inRangeSpecifier && '%' == format[i]) {
                // the result of reading %n is an integer, so replace with d
                newFormat[newFormatCounter++] = 'c';
            } else if (!inRangeSpecifier && '[' == format[i]) {
                // the result of reading %[.*] is a string, so replace with s
                newFormat[newFormatCounter++] = 's';
                inRangeSpecifier = 1;
                inSpecifier = 1; // is still in specifier, this starts the range specifier
            } else if (inRangeSpecifier && ']' == format[i]) {
                inRangeSpecifier = 0;
                inSpecifier = 0;
            } else if (!inRangeSpecifier) {
                newFormat[newFormatCounter++] = format[i];
            }
        } else if (strchr("hljztL", format[i]) != 0) {
            if (!inRangeSpecifier) {
                newFormat[newFormatCounter++] = format[i];
            }
        }
    }
    printf("NewFormat: %s\n", newFormat);
    return newFormat;
}

char searchSpecifier(char* format) {
    for (int i = 1; i < strlen(format); i++) {
        if (strchr("%iudoxfegacsp", format[i]) != 0) {
            return format[i];
        }
    }
    return '\0';
}

int tracerllvm_wrap_fscanf(FILE* stream, const char* format, ...)
{
    char* convFormat = convertFormat(format);
    tracerllvm_addInformation(FSCANF);
    tracerllvm_optOpcode(FSCANF);
    va_list args;
    va_start (args, format);
    va_list copy1;
    va_copy (copy1, args);
    int result;
    if ((result = vfscanf(stream, format, args)) > 0)
    {
        char* ptr = strtok(convFormat, "\31");
        while (ptr != NULL) {
            if (strlen(ptr) >= 2) {
                if (ptr[0] == '%') {
                    char spec = searchSpecifier(ptr);
                    if (strchr("iudoxcp", spec) != 0) {
                        int* argument = va_arg(copy1, int*);
                        size_t needed = snprintf(NULL, 0, ptr, *argument) + 1;
                        char  *buffer = malloc(needed);
                        buffer[needed - 1] = '\0';
                        snprintf(buffer, needed, ptr, *argument);
                        tracerllvm_optInput(fileno(stream), buffer);
                    } else if (strchr("fega", spec) != 0){
                        float* argument = va_arg(copy1, float*);
                        size_t needed = snprintf(NULL, 0, ptr, *argument) + 1;
                        char  *buffer = malloc(needed);
                        buffer[needed - 1] = '\0';
                        snprintf(buffer, needed, ptr, *argument);
                        tracerllvm_optInput(fileno(stream), buffer);
                    } else if (spec == 's'){
                        char* argument = va_arg(copy1, char*);
                        tracerllvm_optInput(fileno(stream), argument);
                    }
                } else {
                    tracerllvm_optInput(fileno(stream), ptr);
                }
            }
            ptr = strtok(NULL, "\31");
        }
//        size_t needed = vsnprintf(NULL, 0, format, copy1) + 1;
//        char  *buffer = malloc(needed);
//        buffer[needed - 1] = '\0';
//        vsnprintf(buffer, needed, format, copy2);
//        printf("Read: %s\n", buffer);
//        tracerllvm_optInput(-1, strdup(format));
//        tracerllvm_optInput(fileno(stream), buffer);
    }
    va_end (args);
    va_end (copy1);
    tracerllvm_instructionEnd();
    free(convFormat);
    return result;
}

ssize_t tracerllvm_wrap_recv(int fd, void* buffer, size_t length, int flags)
{
    tracerllvm_addInformation(READ);
    int result;
    printf("Read new stuff.\n");
    tracerllvm_optOpcode(READ);
    if ((result = recv(fd, buffer, length, flags)) > 0)
    {
        if (length >= 13 && strncmp(buffer, "proFuzzer End", 13) == 0) {
            // we received the end command, the subject will be terminated
            tracerllvm_instructionEnd();
            tracerllvm_endTrace();
            close(fd);
            exit(0);
        }
        void* buf = calloc(1, result + 1);
        strncpy(buf, buffer, result);
        tracerllvm_optInput((uintptr_t)fd, buf);
        free(buf);
    }
    tracerllvm_instructionEnd();
    return result;
}

int tracerllvm_wrap_fork()
{
    //let fork do nothing to avoid multithreading, this is not supported by our tainting engine
    return 0;
}

int tracerllvm_wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg)
{
    //let fork do nothing to avoid multithreading, this is not supported by our tainting engine
    start_routine(arg);
    return 0;
}

int tracerllvm_wrap_exit(int exitcode)
{
    tracerllvm_endTrace();
    exit(exitcode);
}

int tracerllvm_wrap_close(int fd)
{
    //check if program wants to close the tainting file, if so do nothing, else close
    if (tracerllvm_isTaintFile(fd)) {
        return 0;
    }
    return close(fd);
}

int tracerllvm_wrap_fclose(FILE* fd)
{
    //check if program wants to close the tainting file, if so do nothing, else close
    if (tracerllvm_isTaintFile(fileno(fd))) {
        return 0;
    }
    return fclose(fd);
}

int tracerllvm_wrap_open(const char* path, int oflags)
{
    tracerllvm_addInformation(FDBINDING);
    tracerllvm_optOpcode(FDBINDING);
    int result = 0;
    if ((result = open(path, oflags)) >= 0)
    {
        // only if the open call is successful we write out the information we need
        tracerllvm_optInput(result, strdup(path));
    }

    tracerllvm_instructionEnd();
    return result;
}

int tracerllvm_wrap_dup(int fd)
{
    tracerllvm_addInformation(FDBINDING);
    tracerllvm_optOpcode(FDBINDING);
    int result = 0;
    if ((result = dup(fd)) >= 0)
    {
        // only if the dup call is successful we write out the information we need
        char str[22];
        sprintf(str, "%i", fd);
        tracerllvm_optInput(result, str);
    }

    tracerllvm_instructionEnd();
    return result;
}

int tracerllvm_wrap_dup2(int oldfd, int newfd)
{
    tracerllvm_addInformation(FDBINDING);
    tracerllvm_optOpcode(FDBINDING);
    int result = 0;
    if ((result = dup2(oldfd, newfd)) >= 0)
    {
        // only if the dup call is successful we write out the information we need
        char str[22];
        sprintf(str, "%i", oldfd);
        tracerllvm_optInput(result, str);
    }

    tracerllvm_instructionEnd();
    return result;
}

double tracerllvm_wrap_strtod(const char *str, char **endptr)
{
    tracerllvm_addInformation(STRTO);
    tracerllvm_optOpcode(STRTO);
    double result = strtod(str, endptr);
    tracerllvm_optInput((uintptr_t) str, strdup(str));
    if (endptr != NULL) {
        tracerllvm_optInput((uintptr_t) *endptr, *endptr);
    }
    tracerllvm_instructionEnd();
    return result;
}

long double tracerllvm_wrap_strtold(const char *str, char **endptr)
{
    tracerllvm_addInformation(STRTO);
    tracerllvm_optOpcode(STRTO);
    long double result = strtold(str, endptr);
    tracerllvm_optInput((uintptr_t) str, strdup(str));
    if (endptr != NULL) {
        tracerllvm_optInput((uintptr_t) *endptr, *endptr);
    }
    tracerllvm_instructionEnd();
    return result;
}


float tracerllvm_wrap_strtof(const char *str, char **endptr)
{
    tracerllvm_addInformation(STRTO);
    tracerllvm_optOpcode(STRTO);
    float result = strtof(str, endptr);
    tracerllvm_optInput((uintptr_t) str, strdup(str));
    if (endptr != NULL) {
        tracerllvm_optInput((uintptr_t) *endptr, *endptr);
    }
    tracerllvm_instructionEnd();
    return result;
}

long int tracerllvm_wrap_strtol(const char *str, char **endptr, int base)
{
    tracerllvm_addInformation(STRTO);
    tracerllvm_optOpcode(STRTO);
    long int result = strtol(str, endptr, base);
    tracerllvm_optInput((uintptr_t) str, strdup(str));
    if (endptr != NULL) {
        tracerllvm_optInput((uintptr_t) *endptr, *endptr);
    }
    tracerllvm_instructionEnd();
    return result;
}

long long int tracerllvm_wrap_strtoll(const char *str, char **endptr, int base)
{
    tracerllvm_addInformation(STRTO);
    tracerllvm_optOpcode(STRTO);
    long int result = strtoll(str, endptr, base);
    tracerllvm_optInput((uintptr_t) str, strdup(str));
    if (endptr != NULL) {
        tracerllvm_optInput((uintptr_t) *endptr, *endptr);
    }
    tracerllvm_instructionEnd();
    return result;
}

unsigned long int tracerllvm_wrap_strtoul(const char *str, char **endptr, int base)
{
    tracerllvm_addInformation(STRTO);
    tracerllvm_optOpcode(STRTO);
    unsigned long int result = strtoul(str, endptr, base);
    tracerllvm_optInput((uintptr_t) str, strdup(str));
    if (endptr != NULL) {
        tracerllvm_optInput((uintptr_t) *endptr, *endptr);
    }
    tracerllvm_instructionEnd();
    return result;
}

unsigned long long int tracerllvm_wrap_strtoull(const char *str, char **endptr, int base)
{
    tracerllvm_addInformation(STRTO);
    tracerllvm_optOpcode(STRTO);
    unsigned long int result = strtoull(str, endptr, base);
    tracerllvm_optInput((uintptr_t) str, strdup(str));
    if (endptr != NULL) {
        tracerllvm_optInput((uintptr_t) *endptr, *endptr);
    }
    tracerllvm_instructionEnd();
    return result;
}

int tracerllvm_wrap_vsnprintf(char *str, size_t size, const char *format, va_list ap)
{
    if (size == 0) {
        // in this case nothing is written
        return vsnprintf(str, size, format, ap);
    }
//    printf("Start: string %p\n", str);
//    printf("Start: size %zu\n", size);
    tracerllvm_addInformation(VSNPRINTF);
    tracerllvm_optOpcode(VSNPRINTF);

    char* newFormat = calloc(1, size * sizeof(char*) * 3);
    int newFormatCounter = 0; // counter where to save a char in the newFormat string
    int record = 0; // boolean to define if a char should be recorded
    printf("Format String: %s\n", format);
    for (int i = 0; i < strlen(format); i++) {
        if (record) {
            newFormat[newFormatCounter++] = format[i];
        }
        if (strchr("%diufFeEgGxXaAoscpn'", format[i]) != 0 && record) {
            record = 0;
            newFormat[newFormatCounter++] = ' ';
            newFormat[newFormatCounter++] = '\31';
        }
        if (format[i] == '%') {
            record = 1;
            newFormat[newFormatCounter++] = format[i];
        }
    }

    printf("\nExtracted format specifiers: %s\n", newFormat);
    va_list copy;
    va_copy(copy, ap);
    int result = vsnprintf(str, size, format, ap);
//    printf("Before while: return %d\n", result);
//    printf("Before while: string %s\n", str);
//    printf("Before while: string %p\n", str);

    tracerllvm_optInput((uintptr_t) format, strdup(format));
    tracerllvm_optInput((uintptr_t) str, str);

    char* extractedString = malloc(size * sizeof(char*));
    vsnprintf(extractedString, size, newFormat, copy);
//    printf("After second vsnprintf: string %s\n", extractedString);
    char* ptr = strtok(extractedString, "\31");
    while (ptr != NULL) {
        // first remove the additional whitespace introduced when splitting the format string, then print the value
        ptr[strlen(ptr) - 1] = '\0';
        tracerllvm_optInput((uintptr_t) ptr, ptr);
        printf("String: %s\n", ptr);
        ptr = strtok(NULL, "\31");
    }
    printf("\nResulting string: %s\n", extractedString);


    free(newFormat);
    tracerllvm_instructionEnd();
    return result;
}

int tracerllvm_wrap_vsnprintf_chk(char *str, size_t size, int flag, size_t slen, const char *format, va_list ap) {
    // TODO ignore the checker flags for the moment
    return tracerllvm_wrap_vsnprintf(str, size, format, ap);
}

// wrap isX() function as they are expanded from macros on ubuntu
// TODO does not work when compiling bitcode directly!

enum IsXEnum{
    ISUPPER,
    ISLOWER,
    ISALPHA,
    ISDIGIT,
    ISXDIGIT,
    ISSPACE,
    ISPRINT,
    ISGRAPH,
    ISBLANK,
    ISCNTRL,
    ISPUNCT,
    ISALNUM
}IsXEnum;

int tracerllvm_wrap_isdigit(int c) {
    tracerllvm_addInformation(ISX);
    tracerllvm_optOpcode(ISX);
    tracerllvm_optInput(ISDIGIT, "\0");
    return isdigit(c);
}

int tracerllvm_wrap_isupper(int c) {
    tracerllvm_addInformation(ISX);
    tracerllvm_optOpcode(ISX);
    tracerllvm_optInput(ISUPPER, "\0");
    return isupper(c);
}

int tracerllvm_wrap_islower(int c) {
    tracerllvm_addInformation(ISX);
    tracerllvm_optOpcode(ISX);
    tracerllvm_optInput(ISLOWER, "\0");
    return islower(c);
}

int tracerllvm_wrap_isalpha(int c) {
    tracerllvm_addInformation(ISX);
    tracerllvm_optOpcode(ISX);
    tracerllvm_optInput(ISALPHA, "\0");
    return isalpha(c);
}

int tracerllvm_wrap_isxdigit(int c) {
    tracerllvm_addInformation(ISX);
    tracerllvm_optOpcode(ISX);
    tracerllvm_optInput(ISXDIGIT, "\0");
    return isxdigit(c);
}

int tracerllvm_wrap_isspace(int c) {
    tracerllvm_addInformation(ISX);
    tracerllvm_optOpcode(ISX);
    tracerllvm_optInput(ISSPACE, "\0");
    return isspace(c);
}

int tracerllvm_wrap_isprint(int c) {
    tracerllvm_addInformation(ISX);
    tracerllvm_optOpcode(ISX);
    tracerllvm_optInput(ISPRINT, "\0");
    return isprint(c);
}

int tracerllvm_wrap_isgraph(int c) {
    tracerllvm_addInformation(ISX);
    tracerllvm_optOpcode(ISX);
    tracerllvm_optInput(ISGRAPH, "\0");
    return isgraph(c);
}

int tracerllvm_wrap_isblank(int c) {
    tracerllvm_addInformation(ISX);
    tracerllvm_optOpcode(ISX);
    tracerllvm_optInput(ISBLANK, "\0");
    return isblank(c);
}

int tracerllvm_wrap_iscntrl(int c) {
    tracerllvm_addInformation(ISX);
    tracerllvm_optOpcode(ISX);
    tracerllvm_optInput(ISCNTRL, "\0");
    return iscntrl(c);
}

int tracerllvm_wrap_ispunct(int c) {
    tracerllvm_addInformation(ISX);
    tracerllvm_optOpcode(ISX);
    tracerllvm_optInput(ISPUNCT, "\0");
    return ispunct(c);
}

int tracerllvm_wrap_isalnum(int c) {
    tracerllvm_addInformation(ISX);
    tracerllvm_optOpcode(ISX);
    tracerllvm_optInput(ISALNUM, "\0");
    return isalnum(c);
}


//
//void tracerllvm_wrap_method__enter(int i) {
//    tracerllvm_addInformation(CMIMID);
//    tracerllvm_optOpcode(CMIMID);
//
//    tracerllvm_optInput(0, "method_enter");
//    tracerllvm_optInput(i, "");
//    tracerllvm_instructionEnd();
//}
//
//void tracerllvm_wrap_method__exit() {
//    tracerllvm_addInformation(CMIMID);
//    tracerllvm_optOpcode(CMIMID);
//
//    tracerllvm_optInput(0, "method_exit");
//    tracerllvm_instructionEnd();
//}
//
//void tracerllvm_wrap_stack__enter(int i, int j) {
//    tracerllvm_addInformation(CMIMID);
//    tracerllvm_optOpcode(CMIMID);
//
//    tracerllvm_optInput(0, "stack_enter");
//    tracerllvm_optInput(i, "");
//    tracerllvm_optInput(j, "");
//    tracerllvm_instructionEnd();
//}
//
//void tracerllvm_wrap_stack__exit(int i) {
//    tracerllvm_addInformation(CMIMID);
//    tracerllvm_optOpcode(CMIMID);
//
//    tracerllvm_optInput(0, "stack_exit");
//    tracerllvm_optInput(i, "");
//    tracerllvm_instructionEnd();
//}
//
//void tracerllvm_wrap_scope__enter(int i) {
//    tracerllvm_addInformation(CMIMID);
//    tracerllvm_optOpcode(CMIMID);
//
//    tracerllvm_optInput(0, "scope_enter");
//    tracerllvm_optInput(i, "");
//    tracerllvm_instructionEnd();
//}
//
//void tracerllvm_wrap_scope__exit(int i) {
//    tracerllvm_addInformation(CMIMID);
//    tracerllvm_optOpcode(CMIMID);
//
//    tracerllvm_optInput(0, "scope_exit");
//    tracerllvm_optInput(i, "");
//    tracerllvm_instructionEnd();
//}

//int tracerllvm_wrap_dup3(int oldfd, int newfd, int flags)
//{
//    tracerllvm_addInformation(FDBINDING);
//    tracerllvm_optOpcode(FDBINDING);
//    int result = 0;
//    if ((result = dup3(oldfd, newfd, flags)) >= 0)
//    {
//        // only if the dup call is successful we write out the information we need
//        char str[22];
//        sprintf(str, "%i", result);
//        tracerllvm_optInput(result, str);
//    }
//
//    tracerllvm_instructionEnd();
//    return result;
//}

// gets was removed in C11 so it might not be defined
#ifdef gets
char* tracerllvm_wrap_gets(char* restrict str)
{
    tracerllvm_addInformation(FGETS);
    tracerllvm_optOpcode(FGETS);
    char* result;
    if ((result = gets(str)) != NULL)
    {
        tracerllvm_optInput((uintptr_t)stdin, result);
    }

    tracerllvm_instructionEnd();
    return result;
}
#endif

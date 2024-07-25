#pragma once

#define _FILE_OFFSET_BITS 64
#include "urmem.hpp"
#include <subhook.h>

#define UnreadBits(ptr) (*((unsigned long *)(ptr) + 2) > *((unsigned long *)(ptr)) ? 0 : *((unsigned long *)(ptr)) - *((unsigned long *)(ptr) + 2))

#ifdef _WIN32
    #define READ_BITS_PATTERN "\x8B\x54\x24\x08\x85\xD2\x56\x8B\xF1\x7E\x0B\x8B\x46\x08\x8B\x0E"
    #define READ_BITS_MASK    "xxxxxxxxxxxxxxxx"

    #define CALL __stdcall
    #define EXTERN extern "C"
#elif __linux__
    #define READ_BITS_PATTERN "\x55\x31\xD2\x89\xE5\x57\x56\x53\x83\xEC\x1C\x8B\x75\x10\x0F\xB6\x45\x14\x8B\x7D\x08\x85\xF6\x8B\x5D\x0C"
    #define READ_BITS_MASK    "xxxxxxxxxxxxxxxxxxxxxxxxxx"

    #define __thiscall
    #define CALL
    #define EXTERN extern "C" __attribute__((visibility("default")))
#endif

using r_bits = bool(__thiscall*)(void*, unsigned char*, int, bool);
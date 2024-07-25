#pragma once

#include "urmem.hpp"
#ifdef _WIN32
    #define PATTERN "\x8B\x54\x24\x08\x85\xD2\x56\x8B\xF1\x7E\x0B\x8B\x46\x08\x8B\x0E"
    #define MASK    "xxxxxxxxxxxxxxxx"
    #define CALL __stdcall
    #define EXTERN extern "C"
#elif __linux__
    #define PATTERN "\x55\x31\xD2\x89\xE5\x57\x56\x53\x83\xEC\x1C\x8B\x75\x10\x0F\xB6\x45\x14\x8B\x7D\x08\x85\xF6\x8B\x5D\x0C"
    #define MASK    "xxxxxxxxxxxxxxxxxxxxxxxxxx"
    #define CALL
    #define EXTERN extern "C" __attribute__((visibility("default")))
#endif
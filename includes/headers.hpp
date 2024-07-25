#pragma once

#include "urmem.hpp"
#ifdef _WIN32
    #define READ_BITS "\x7E\x06\x32\xC0\x5E\xC2\x0C\x00"
    #define READ_BITS_MASK "xxxxxxxx"

    #define CALL __stdcall
    #define EXTERN extern "C"
#elif __linux__
    #define READ_BITS "\x7E\x0A\x83\xC4\x1C\x89\xD0"
    #define READ_BITS_MASK "xxxxxxx"
    #define CALL
    #define EXTERN extern "C" __attribute__((visibility("default")))
#endif
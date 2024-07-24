#include "headers.hpp"

#ifdef _WIN32
    #define PATTERN "\x8B\xE9\x57\xC1\xE9\x02\x33\xC0\x8B\xFB\xF3\xAB\x8B\xCD"
    #define MASK    "xxxxxxxxxxxxxx"
    #define OFFSET  0x28
    #define CALL __stdcall
    #define EXTERN extern "C"
#elif __linux__
    #define PATTERN "\x0F\xB6\x04\x10\x0F\xB6\x13\xD3\xE0"
    #define MASK    "xxxxxxxxx"
    #define OFFSET  0x7B
    #define __fastcall
    #define CALL
    #define EXTERN extern "C" __attribute__((visibility("default")))
#endif

std::pair<urmem::hook, urmem::address_t> hook;
bool __fastcall read_bits(void* ptr, void* edx, unsigned char* output, int num_to_read, bool align_to_read) {
    int NumberOfUnreadBits = *((unsigned long *)ptr) - *((unsigned long *)ptr + 2);
    if(NumberOfUnreadBits < num_to_read) return false;
    #ifdef _WIN32
        return hook.first.call<urmem::calling_convention::thiscall, bool>(ptr, output, num_to_read, align_to_read);
    #elif __linux
        return hook.first.call<urmem::calling_convention::cdeclcall, bool>(ptr, output, num_to_read, align_to_read);
    #endif
};

EXTERN bool CALL Load(void **ppData)
{
    urmem::sig_scanner scanner;
    scanner.init(reinterpret_cast<urmem::address_t>(ppData[0]));
    if(!scanner.find(PATTERN, MASK, hook.second)) return false;
    hook.first.install(hook.second - OFFSET, urmem::get_func_addr(&read_bits));
    return true;
}

EXTERN unsigned int CALL Supports() { return 0x0200 | 0x10000; };
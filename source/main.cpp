#include "headers.hpp"

urmem::sig_scanner scanner;
std::pair<subhook::Hook, urmem::address_t> read_bits_hook;

#ifdef _WIN32
bool __fastcall read_bits(void* ptr, void* edx, unsigned char* output, int num_to_read, bool align_to_read) {
#elif __linux__
bool read_bits(void* ptr, unsigned char* output, int num_to_read, bool align_to_read) {
#endif
    if(UnreadBits(ptr) < num_to_read) return false;
    auto orig = (r_bits)read_bits_hook.first.GetTrampoline();
    return !orig ? false : orig(ptr, output, num_to_read, align_to_read);
};

EXTERN bool CALL Load(void **ppData) { 
    if(!scanner.init(reinterpret_cast<urmem::address_t>(ppData[0]))) return false;
    if(!scanner.find(READ_BITS_PATTERN, READ_BITS_MASK, read_bits_hook.second)) return false;
    return read_bits_hook.first.Install((void*)(read_bits_hook.second), (void*)read_bits, subhook::HookFlagTrampoline);
};

EXTERN unsigned int CALL Supports() { return 0x0200 | 0x10000; };
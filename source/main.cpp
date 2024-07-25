#include "headers.hpp"

urmem::sig_scanner scanner;
std::pair<urmem::hook, urmem::address_t> hook;

#ifdef _WIN32
    bool __fastcall read_bits(void* ptr, void* edx, unsigned char* output, int num_to_read, bool align_to_read) {
#elif __linux__
    bool read_bits(void* ptr, unsigned char* output, int num_to_read, bool align_to_read) {
#endif
    int NumberOfUnreadBits =  *((unsigned long *)ptr + 2) > *((unsigned long *)ptr) ? 0 : *((unsigned long *)ptr) - *((unsigned long *)ptr + 2);
    if(NumberOfUnreadBits < num_to_read) return false;
    return hook.first.call<urmem::calling_convention::thiscall, bool>(ptr, output, num_to_read, align_to_read);
};

EXTERN bool CALL Load(void **ppData)
{ 
    if(!scanner.init(reinterpret_cast<urmem::address_t>(ppData[0]))) return false;
    if(!scanner.find(PATTERN, MASK, hook.second)) return false;
    hook.first.install(hook.second, urmem::get_func_addr(&read_bits));
    return true;
}

EXTERN unsigned int CALL Supports() { return 0x0200 | 0x10000; };
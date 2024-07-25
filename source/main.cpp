#include "headers.hpp"

urmem::sig_scanner scanner;
urmem::address_t read_bits_offset = 0;

EXTERN bool CALL Load(void **ppData) {
    if(!scanner.init(reinterpret_cast<urmem::address_t>(ppData[0]))) return false;
    if(!scanner.find(READ_BITS, READ_BITS_MASK, read_bits_offset)) return false;
    
    urmem::unprotect_memory(read_bits_offset, 1);
    *(unsigned char*)read_bits_offset = 0x76;
    return true;
};

EXTERN unsigned int CALL Supports() { return 0x0200 | 0x10000; };
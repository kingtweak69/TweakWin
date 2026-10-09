#include "pe.h"

#include <stddef.h>

const char *tw_pe_machine_name(uint16_t machine)
{
    switch (machine) {
    case TW_PE_MACHINE_UNKNOWN: return "unknown";
    case TW_PE_MACHINE_I386:    return "i386";
    case TW_PE_MACHINE_ARMNT:   return "armnt";
    case TW_PE_MACHINE_IA64:    return "ia64";
    case TW_PE_MACHINE_AMD64:   return "x86_64";
    case TW_PE_MACHINE_ARM64EC: return "arm64ec";
    case TW_PE_MACHINE_ARM64:   return "arm64";
    case 0x01c0:                return "arm";
    case 0x0ebc:                return "efi-bytecode";
    case 0x5064:                return "riscv64";
    default:                    return "unrecognized";
    }
}

const char *tw_pe_subsystem_name(uint16_t subsystem)
{
    switch (subsystem) {
    case 0:  return "Unknown";
    case 1:  return "Native";
    case 2:  return "Windows GUI";
    case 3:  return "Windows Console";
    case 5:  return "OS/2 Console";
    case 7:  return "POSIX Console";
    case 8:  return "Native Win9x Driver";
    case 9:  return "Windows CE GUI";
    case 10: return "EFI Application";
    case 11: return "EFI Boot Service Driver";
    case 12: return "EFI Runtime Driver";
    case 13: return "EFI ROM";
    case 14: return "Xbox";
    case 16: return "Windows Boot Application";
    default: return "Unrecognized";
    }
}

const char *tw_pe_dir_name(unsigned index)
{
    static const char *const names[TW_PE_DIR_COUNT] = {
        "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC",
        "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG",
        "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "CLR_RUNTIME", "RESERVED",
    };
    return index < TW_PE_DIR_COUNT ? names[index] : "?";
}

const char *tw_pe_reloc_type_name(unsigned type)
{
    switch (type) {
    case TW_PE_REL_ABSOLUTE: return "ABSOLUTE";
    case TW_PE_REL_HIGH:     return "HIGH";
    case TW_PE_REL_LOW:      return "LOW";
    case TW_PE_REL_HIGHLOW:  return "HIGHLOW";
    case TW_PE_REL_HIGHADJ:  return "HIGHADJ";
    case TW_PE_REL_DIR64:    return "DIR64";
    default:                 return NULL;
    }
}

const char *tw_pe_rsrc_type_name(uint32_t id)
{
    switch (id) {
    case 1:  return "CURSOR";
    case 2:  return "BITMAP";
    case 3:  return "ICON";
    case 4:  return "MENU";
    case 5:  return "DIALOG";
    case 6:  return "STRING";
    case 7:  return "FONTDIR";
    case 8:  return "FONT";
    case 9:  return "ACCELERATOR";
    case 10: return "RCDATA";
    case 11: return "MESSAGETABLE";
    case 12: return "GROUP_CURSOR";
    case 14: return "GROUP_ICON";
    case 16: return "VERSION";
    case 17: return "DLGINCLUDE";
    case 19: return "PLUGPLAY";
    case 20: return "VXD";
    case 21: return "ANICURSOR";
    case 22: return "ANIICON";
    case 23: return "HTML";
    case 24: return "MANIFEST";
    default: return NULL;
    }
}

const char *tw_pe_status_name(tw_pe_status st)
{
    switch (st) {
    case TW_PE_OK:              return "ok";
    case TW_PE_ERR_IO:          return "i/o error";
    case TW_PE_ERR_NOMEM:       return "out of memory";
    case TW_PE_ERR_MALFORMED:   return "malformed";
    case TW_PE_ERR_UNSUPPORTED: return "unsupported";
    default:                    return "?";
    }
}

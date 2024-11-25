#include <stdint.h>
#include <dlfcn.h>
#include <link.h>
#include "DlpiUnwindInfo.hpp"
#include "dwarf2.h"

#if defined(__linux)
#include "linux.hpp"
#elif defined(__FreeBSD__)
#include "freebsd.hpp"
#endif

#ifndef ElfW
#if __SIZEOF_POINTER__ == 4
#define ElfW(T) Elf32_##T
#elif __SIZEOF_POINTER__ == 8
#define ElfW(T) Elf64_##T
#else
#error Unknown architecture
#endif
#endif

namespace dwarf {
    DlpiUnwindInfo::DlpiUnwindInfo(uintptr_t ra, bool signal_frame): UnwindInfo(ra, signal_frame)
    {
        dl_iterate_phdr(callback, this);

#if defined(PSEUDO_SIGNAL_FRAME)
        if (!eh_frame_hdr || !eh_frame_hdr_size) {
            if ((ra >= signal_eh_frame.eh_frame.fde.location) &&
                (ra < signal_eh_frame.eh_frame.fde.location + signal_eh_frame.eh_frame.fde.address_range)) {
                // pseudo .eh_frame and .eh_frame_hdr are used if .eh_frame_hdr is missing in vdso.
                eh_frame_hdr = (struct eh_frame_hdr *)&signal_eh_frame.eh_frame_hdr;
                eh_frame_hdr_size = sizeof(signal_eh_frame.eh_frame_hdr);
            }
        }
#endif // define(PSEUDO_SIGNAL_FRAME)
    }

    int DlpiUnwindInfo::callback(struct dl_phdr_info *info, size_t size, void *data)
    {
        DlpiUnwindInfo *self = (DlpiUnwindInfo *)data;

        for (unsigned int i = 0; i < info->dlpi_phnum; ++i) {
            uintptr_t begin = info->dlpi_addr + info->dlpi_phdr[i].p_vaddr;
            uintptr_t end = begin + info->dlpi_phdr[i].p_memsz;
            if ((self->ra >= begin) && (self->ra < end)) {
                self->tbase = info->dlpi_phdr[i].p_vaddr + info->dlpi_addr;

                // Find .eh_frame_hdr section
                for (unsigned int i = 0; i < info->dlpi_phnum; ++i) {
                    if (info->dlpi_phdr[i].p_type == PT_GNU_EH_FRAME) {
                        self->eh_frame_hdr = (struct eh_frame_hdr *)(info->dlpi_phdr[i].p_vaddr + info->dlpi_addr);
                        self->eh_frame_hdr_size = info->dlpi_phdr[i].p_memsz;
                        break;
                    }
                }

                // Find .got section
                for (unsigned int i = 0; i < info->dlpi_phnum; ++i) {
                    if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
                        ElfW(Dyn) *dyn = (ElfW(Dyn) *)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
                        while (dyn->d_tag != DT_NULL) {
                            if (dyn->d_tag == DT_PLTGOT) {
                                self->dbase = dyn->d_un.d_ptr;
                                break;
                            }

                            ++dyn;
                        }

                        break;
                    }
                }

                return 1;
            }
        }

        return 0;
    }
} // namespace dwarf

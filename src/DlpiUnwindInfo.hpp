#ifndef DLPI_UNWIND_INFO_HPP
#define DLPI_UNWIND_INFO_HPP

#include "dwarf.hpp"

namespace dwarf {

    class DlpiUnwindInfo: public UnwindInfo
    {
    public:
        DlpiUnwindInfo(uintptr_t ra, bool signal_frame);

    private:
        static int callback(struct dl_phdr_info *info, size_t size, void *data);
    };
} // namespace dwarf

#endif // DLPI_UNWIND_INFO_HPP

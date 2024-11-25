#include "dwarf.hpp"
#include "DlpiUnwindInfo.hpp"

typedef dwarf::UnwindCursor<dwarf::DlpiUnwindInfo> UnwindCursor;

extern "C" {

int unw_init_local(unw_cursor_t *cursor, unw_context_t *context)
{
    if (sizeof(unw_cursor_t) < sizeof(UnwindCursor))
        return UNW_EINVAL;
    new(cursor) UnwindCursor(*(Registers *)context);
    return ((UnwindCursor *)cursor)->init();
}

int unw_init_local2(unw_cursor_t *cursor, unw_context_t *context, int flags)
{
    if (sizeof(unw_cursor_t) < sizeof(UnwindCursor))
        return UNW_EINVAL;
    new(cursor) UnwindCursor(*(Registers *)context);
    return ((UnwindCursor *)cursor)->init(flags);
}

int unw_get_reg(unw_cursor_t *cursor, unw_regnum_t reg, unw_word_t *value)
{
    return ((UnwindCursor *)cursor)->get_reg(reg, value);
}

int unw_set_reg(unw_cursor_t *cursor, unw_regnum_t reg, unw_word_t value)
{
    return ((UnwindCursor *)cursor)->set_reg(reg, value);
}

int unw_get_fpreg(unw_cursor_t *cursor, unw_regnum_t reg, unw_fpreg_t *value)
{
    return ((UnwindCursor *)cursor)->get_fpreg(reg, value);
}

int unw_set_fpreg(unw_cursor_t *cursor, unw_regnum_t reg, unw_fpreg_t value)
{
    return ((UnwindCursor *)cursor)->set_fpreg(reg, value);
}

const char *unw_regname(unw_cursor_t *cursor, unw_regnum_t reg)
{
    return ((UnwindCursor *)cursor)->regname(reg);
}

int unw_step(unw_cursor_t *cursor)
{
    return ((UnwindCursor *)cursor)->step();
}

int unw_get_proc_info(unw_cursor_t *cursor, unw_proc_info_t *info)
{
    return ((UnwindCursor *)cursor)->get_proc_info(info);
    return UNW_EINVAL;
}

int unw_is_signal_frame(unw_cursor_t *cursor)
{
    return ((UnwindCursor *)cursor)->is_signal_frame();
}

int unw_resume(unw_cursor_t *cursor)
{
    ((UnwindCursor *)cursor)->resume();
    return UNW_EUNSPEC;
}

} // extern "C"

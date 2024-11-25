#ifndef ARM_EHABI_HPP
#define ARM_EHABI_HPP

#include <stdint.h>
#include "Registers.hpp"

namespace ehabi {

#define EXIDX_CANTUNWIND 0x01

    //PT_ARM_EXIDX

    struct exidx {
        uint32_t offset;
        uint32_t value;
    };

    struct UnwindInfo
    {
        UnwindInfo(uintptr_t ra, bool signal_frame):
            ra(ra), tbase(0), dbase(0), exidx(0), exidx_size(0), signal_frame(signal_frame ? 1 : 0)
        {}

        operator bool() const
        {
            return false;
        }

        uintptr_t ra;
        uintptr_t dbase;
        uintptr_t tbase;
        const struct exidx *exidx;
        size_t exidx_size;
        int signal_frame:1;
    };

    template<Architecture arch> 
    class CFI
    {
    public:
        enum { HIGHEST_DWARF_REGISTER = Registers<arch>::HIGHEST_DWARF_REGISTER, };

        CFI():
            __expression(nullptr), __size(0)
        {}

        int get(Registers<arch> &regs) const
        {
            return get(regs, __expression, __expression + __size);
        }

        int get_proc_info(unw_proc_info_t *info)
        {
            return UNW_ESUCCESS;
        }

        int is_signal_frame()
        {
            return 0;
        }

        int parse(const UnwindInfo &unwind_info)
        {
            const unsigned char *ptr = (const unsigned char *)unwind_info.exidx;
            const unsigned char *end = ptr + unwind_info.exidx_size;

            size_t range = unwind_info.exidx_size / sizeof(struct exidx);
            if (!range)
                return UNW_ENOINFO;

            const struct exidx *exidx = unwind_info.exidx;
            uintptr_t ra = unwind_info.ra - (unwind_info.signal_frame ^ 0x01);

            // find 
            for ( ; ; ) {
                const struct exidx *p = exidx + range/2;
                uintptr_t location = p->offset;
                if (location & 0x80000000)
                    return UNW_EINVAL;
                location += (uintptr_t)&p->offset;

                if (ra < location) {
                    if (!(range /= 2))
                        return UNW_ENOINFO;
                } else {
                    if (range < 2)
                        break;

                    exidx = p;
                    range -= range/2;
                }
            }

            if (exidx->value == EXIDX_CANTUNWIND)
                return UNW_EINVAL;

            const unsigned char *expression;
            size_t size;
            if (exidx->value & 0x80000000) {
                // exception-handling table entry is encoded inline
                expression = (const unsigned char *)&exidx->value;
                switch (exidx->value >> 24) {
                    case 0: // short description
                        expression += 1;
                        size = 3;
                        break;
                    case 1: // long description
                    case 2:
                        if (exidx->value & 0x00FF0000)
                            return UNW_EINVAL;
                        expression += 2;
                        size = 2;
                        break;
                    default:
                        return UNW_EINVAL;
                }
            } else {
                // prel31 encoded address of exception-handling table entry
                expression = (const unsigned char *)&exidx->value + exidx->value;
                if (expression[0] & 0x80) {
                    // Generic mode
                    size = 4 * expression[4] + 3;
                    expression += 5;
                } else {
                    // Compact mode 
                    switch (expression[0]) {
                        case 0:
                            expression += 1;
                            size = 3;
                        case 1:
                        case 2:
                            size = 4 * expression[1] + 2;
                            expression += 2;
                            break;
                        default:
                            return UNW_EINVAL;
                    }
                }
            }

            // parse unwind instructions
            __expression = expression;
            __size = size;
            return 0;
        }

    private:
        int get(Registers<arch> &regs, const unsigned char *ptr, const unsigned char *end)
        {
            while (ptr != end) {
                unsigned char op = *ptr++;
                switch (op >> 4) {
                    case 0x00:
                    case 0x01:
                    case 0x02:
                    case 0x03: // 00xxxxxx: vsp = vsp + (xxxx << 2) + 4
                        regs.set_sp(regs.get_sp() + (op << 2) + 4);
                        break;
                    case 0x04:
                    case 0x05:
                    case 0x06:
                    case 0x07: // 0xxxxx: vsp = vsp - (xxxx << 2) - 4
                        regs.set_sp(regs.get_sp() - ((op & 0x3f) << 2) + 4);
                        break;
                    case 0x08: { // 10000000 000000 | 1000iiii iiiiiiii
                        if (ptr == end)
                            return UNW_EINVAL;
                        unsigned int mask = ((op & 0x0f) << 4) + *ptr++;
                        if (mask == 0)
                            return UNW_EINVAL;
                        unsigned int sp_restored = mask & 0x200;
                        unw_word_t sp = regs.get_sp();
                        do {
                            unsigned int i = __builtin_ctz(mask);
                            unsigned int reg = 4 + i;
                            regs.set_reg(reg, *(unw_word_t *)sp);
                            sp += sizeof(unw_word_t);
                            mask ^= 1 << i;
                        } while (mask);
                        if (!sp_restored)
                            regs.set_sp(sp);
                        break;
                    }
                    case 0x09: { // 1001nnnn
                        unsigned int reg = op & 0x0f;
                        if ((reg == 13) || (reg == 15))
                            return UNW_EINVAL;
                        unw_word_t val;
                        if (!regs.get_reg(reg, &val))
                            return UNW_EBADREG;
                        regs.set_sp(val);
                        break;
                    }
                    case 0x0A: { // 10100nnn 10101nnn
                        unsigned int n = op & 0x07;
                        unw_word_t sp = regs.get_sp();
                        for (unsigned int i = 0; i <= n; ++i) {
                            regs.set_reg(4 + i, *(unw_word_t *)sp);
                            sp += sizeof(unw_word_t);
                        }

                        if (op & 0x08) {
                            regs.set_reg(14, *(unw_word_t *)sp);
                            sp += sizeof(unw_word_t);
                        }

                        regs.set_sp(sp);
                        break;
                    }
                    case 0x0B: {
                        switch (op & 0x0F) {
                            case 0x00:  // 10110000
                                return UNW_ESUCCESS; // Finish
                            case 0x01: { // 10110001 0000iiii
                                if (ptr == end)
                                    return UNW_EINVAL;
                                unsigned int mask = *ptr++;
                                if ((mask == 0) || (mask & 0xF0))
                                    return UNW_EINVAL; // SPARE: 10110001 00000000 | 10110001 xxxxyyyy
                                unw_word_t sp = regs.get_sp(); 
                                do {
                                    unsigned int i = __builtin_ctz(mask);
                                    regs.set_reg(i, *(unw_word_t *)sp);
                                    sp += sizeof(unw_word_t);
                                    mask ^= 1 << i;
                                } while (mask);
                                regs.set_sp(sp);
                                break;
                            }
                            case 0x02: { // 10110010 uleb128
                                ULEB128 uleb128;
                                ptr = deserialize(&uleb128, ptr, end);
                                if (!ptr)
                                    return UNW_EINVAL;
                                unw_word_t sp = regs.get_sp();
                                regs.set_sp(sp + 0x204 + (uleb128 << 2));
                                break;
                            }
                            case 0x03: { // 10110011 sssscccc
                                if (ptr == end)
                                    return UNW_EINVAL;
                                unsigned int x = *ptr++;
                                unsigned int i = x >> 4;
                                unsigned int n = i + (x & 0x0F);
                                unw_word_t sp = regs.get_sp();
                                while (i <= n) {
                                    if (!regs.set_fpreg(i, *(unw_fpreg_t *)sp))
                                        return UNW_EBADREG;
                                    sp += sizeof(unw_fpreg_t);
                                }

                                sp += 4;
                                regs.set_sp(sp);
                                break;
                            }
                            case 0x04:
                            case 0x05:
                            case 0x06:
                            case 0x07:
                                return UNW_EINVAL; // 101101nn
                            default: { // 10111nnn
                                unsigned int i = 8;
                                unsigned int n = op & 0x0F;
                                unw_word_t sp = regs.get_sp();
                                while (i <= n) {
                                    if (!regs.set_fpreg(i, *(unw_fpreg_t *)sp))
                                        return UNW_EBADREG;
                                    sp += sizeof(unw_fpreg_t);
                                }

                                sp += 4;
                                regs.set_sp(sp);
                            }
                        }

                        break;
                    }
                    case 0x0C: {
                        switch (op & 0x0F) {
                            case 0x00:
                            case 0x01:
                            case 0x02:
                            case 0x03:
                            case 0x04:
                            case 0x05: { // 11000nnn
                                unsigned int i = 10;
                                unsigned int n = 10 + (op & 0x0F);
                                unw_word_t sp = regs.get_sp();
                                while (i <= n) {
                                    if (!regs.set_fpreg(i, *(unw_fpreg_t *)sp))
                                        return UNW_EBADREG;
                                    sp += sizeof(unw_fpreg_t);
                                }

                                regs.set_sp(sp);
                                break;
                            }
                            case 0x06: { // 11000110 sssscccc
                                if (ptr == end)
                                    return UNW_EINVAL;
                                unsigned int x = *ptr++;
                                unsigned int i = x >> 4;
                                unsigned int n = i + (x & 0x0F);
                                unw_word_t sp = regs.get_sp();
                                while (i <= n) {
                                    if (!regs.set_fpreg(i, *(unw_fpreg_t *)sp))
                                        return UNW_EBADREG;
                                    sp += sizeof(unw_fpreg_t);
                                }

                                regs.set_sp(sp);
                                break;
                            }
                            case 0x07: { // 11000111 0000iiii
                                if (ptr == end)
                                    return UNW_EINVAL;
                                unsigned int mask = *ptr++;
                                if ((mask == 0) || (mask & 0xF0))
                                    return UNW_EINVAL; // SPARE: 11000111 00000000 | 11000111 xxxxyyyy
                                unw_word_t sp = regs.get_sp(); 
                                do {
                                    unsigned int i = __builtin_ctz(mask);
                                    regs.set_reg(i, *(unw_word_t *)sp);
                                    sp += sizeof(unw_word_t);
                                    mask ^= 1 << i;
                                } while (mask);
                                regs.set_sp(sp);
                                break;
                            }
                            case 0x08:
                            case 0x09: { // 11011000 sssscccc | 11011001 sssscccc
                                if (ptr == end)
                                    return UNW_EINVAL;
                                unsigned int x = *ptr++;
                                unsigned int i = (x >> 4) + (((op & 0x01) ^ 0x01) << 4);
                                unsigned int n = i + (x & 0x0F);
                                unw_word_t sp = regs.get_sp();
                                while (i <= n) {
                                    if (!regs.set_fpreg(i, *(unw_fpreg_t *)sp))
                                        return UNW_EBADREG;
                                    sp += sizeof(unw_fpreg_t);
                                }

                                regs.set_sp(sp);
                                break;
                            }
                            default: // 11001yyy
                                return UNW_EINVAL;
                        }

                        break;
                    }
                    case 0x0D: { // 110110nn
                        if (op & 0x80)
                            return UNW_EINVAL;
                        unsigned int i = 8;
                        unsigned int n = 8 + (op & 0x0F);
                        unw_word_t sp = regs.get_sp();
                        while (i <= n) {
                            if (!regs.set_fpreg(i, *(unw_fpreg_t *)sp))
                                return UNW_EBADREG;
                            sp += sizeof(unw_fpreg_t);
                        }

                        regs.set_sp(sp);
                        break;
                    }
                    default:
                        return UNW_EINVAL;
                }
            }

            return UNW_ESUCCESS;
        }

    private:
        const unsigned char *__expression;
        size_t __size;
    };
} // namespace ehabi

#endif // ARM_EHABI_HPP

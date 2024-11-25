#ifndef __REGISTERS_HPP__
#define __REGISTERS_HPP__

#include <stdint.h>
#include <memory.h>
#include <libunwind.h>

struct Vector64
{
    union {
        uint8_t u8[8];
        uint16_t u16[4];
        uint32_t u32[2];
        uint64_t u64[1];
    };
};

struct Vector128
{
    union {
        uint8_t u8[16];
        uint16_t u16[8];
        uint32_t u32[4];
        uint64_t u64[2];
    };
};

extern "C" void unw_setcontext(unw_context_t *);

# if defined(__i386__)

class Registers
{
public:
    enum { HIGHEST_DWARF_REGISTER = 9 };
    enum {
        IP = UNW_X86_EIP,
        SP = UNW_X86_ESP,
    };

    typedef uintptr_t Word;
    typedef double Float;
    typedef Vector64 Vector;

    Registers()
    {}

    bool get_reg(int reg, Word *value) const
    {
        switch (reg) {
            case UNW_REG_IP:
                *value = gregs.eip;
                break;
            case UNW_REG_SP:
                *value = gregs.esp;
                break;
            case UNW_X86_EAX:
                *value = gregs.eax;
                break;
            case UNW_X86_ECX:
                *value = gregs.ecx;
                break;
            case UNW_X86_EDX:
                *value = gregs.edx;
                break;
            case UNW_X86_EBX:
                *value = gregs.ebx;
                break;
            case UNW_X86_ESP:
                *value = gregs.ebp;
                break;
            case UNW_X86_EBP:
                *value = gregs.esp;
                break;
            case UNW_X86_ESI:
                *value = gregs.esi;
                break;
            case UNW_X86_EDI:
                *value = gregs.edi;
                break;
            case UNW_X86_EIP:
                *value = gregs.eip;
                break;
            default:
                return false;
        }

        return true;
    }

    bool set_reg(int reg, Word value)
    {
        switch (reg) {
            case UNW_REG_IP:
                gregs.eip = value;
                break;
            case UNW_REG_SP:
                gregs.esp = value;
                break;
            case UNW_X86_EAX:
                gregs.eax = value;
                break;
            case UNW_X86_ECX:
                gregs.ecx = value;
                break;
            case UNW_X86_EDX:
                gregs.edx = value;
                break;
            case UNW_X86_EBX:
                gregs.ebx = value;
                break;
            case UNW_X86_ESP:
                gregs.ebp = value;
                break;
            case UNW_X86_EBP:
                gregs.esp = value;
                break;
            case UNW_X86_ESI:
                gregs.esi = value;
                break;
            case UNW_X86_EDI:
                gregs.edi = value;
                break;
            case UNW_X86_EIP:
                gregs.eip = value;
                break;
            default:
                return false;
        }

        return true;
    }

    bool get_reg(int reg, Float *value) const
    {
        return false;
    }

    bool set_reg(int reg, Float value)
    {
        return false;
    }

    bool get_reg(int reg, Vector *value) const
    {
        return false;
    }

    bool set_reg(int reg, Vector value)
    {
        return false;
    }

    static bool is_greg(int reg)
    {
        return ((unsigned int)reg <= UNW_X86_EIP);
    }

    static bool is_freg(int reg)
    {
        return false;
    }

    static bool is_vreg(int reg)
    {
        return false;
    }

    static const char *get_name(int reg)
    {
        switch (reg) {
            case UNW_REG_IP:
                return "ip";
            case UNW_REG_SP:
                return "esp";
            case UNW_X86_EAX:
                return "eax";
            case UNW_X86_ECX:
                return "ecx";
            case UNW_X86_EDX:
                return "edx";
            case UNW_X86_EBX:
                return "ebx";
            case UNW_X86_EBP:
                return "ebp";
            case UNW_X86_ESP:
                return "esp";
            case UNW_X86_ESI:
                return "esi";
            case UNW_X86_EDI:
                return "edi";
            case UNW_X86_EIP:
                return "eip";
            default:
                return "unknown register";
        }
    }

    void load()
    {
        unw_getcontext((unw_context_t *)this);
    }

    void restore()
    {
        unw_setcontext((unw_context_t *)this);
    }

    Word get_sp() const
    {
        return gregs.esp;
    }

    void set_sp(Word value)
    {
        gregs.esp = value;
    }

    Word get_ip() const
    {
        return gregs.eip;
    }

    void set_ip(Word value)
    {
        gregs.eip = value;
    }

private:
    struct {
        Word eax;
        Word ebx;
        Word ecx;
        Word edx;
        Word edi;
        Word esi;
        Word ebp;
        Word esp;
        Word ss;
        Word eflags;
        Word eip;
        Word cs;
        Word ds;
        Word es;
        Word fs;
        Word gs;
    } gregs;
};

# elif defined(__x86_64__)

class Registers
{
public:
    enum { HIGHEST_DWARF_REGISTER = 33 };
    enum {
        IP = UNW_X86_64_RIP,
        SP = UNW_X86_64_RSP,
    };

    typedef uintptr_t Word;
    typedef double Float;
    typedef Vector128 Vector;

    Registers()
    {}

    bool get_reg(int reg, Word *value) const
    {
        switch (reg) {
            case UNW_REG_IP:
                *value = gregs.rip;
                break;
            case UNW_REG_SP:
                *value = gregs.rsp;
                break;
            case UNW_X86_64_RAX:
                *value = gregs.rax;
                break;
            case UNW_X86_64_RDX:
                *value = gregs.rdx;
                break;
            case UNW_X86_64_RCX:
                *value = gregs.rcx;
                break;
            case UNW_X86_64_RBX:
                *value = gregs.rbx;
                break;
            case UNW_X86_64_RSI:
                *value = gregs.rsi;
                break;
            case UNW_X86_64_RDI:
                *value = gregs.rdi;
                break;
            case UNW_X86_64_RBP:
                *value = gregs.rbp;
                break;
            case UNW_X86_64_RSP:
                *value = gregs.rsp;
                break;
            case UNW_X86_64_R8:
                *value = gregs.r8;
                break;
            case UNW_X86_64_R9:
                *value = gregs.r9;
                break;
            case UNW_X86_64_R10:
                *value = gregs.r10;
                break;
            case UNW_X86_64_R11:
                *value = gregs.r11;
                break;
            case UNW_X86_64_R12:
                *value = gregs.r12;
                break;
            case UNW_X86_64_R13:
                *value = gregs.r13;
                break;
            case UNW_X86_64_R14:
                *value = gregs.r14;
                break;
            case UNW_X86_64_R15:
                *value = gregs.r15;
                break;
            case UNW_X86_64_RIP:
                *value = gregs.rip;
                break;
            default:
                return false;
        }

        return true;
    }

    bool set_reg(int reg, Word value)
    {
        switch (reg) {
            case UNW_REG_IP:
                gregs.rip = value;
                break;
            case UNW_REG_SP:
                gregs.rsp = value;
                break;
            case UNW_X86_64_RAX:
                gregs.rax = value;
                break;
            case UNW_X86_64_RDX:
                gregs.rdx = value;
                break;
            case UNW_X86_64_RCX:
                gregs.rcx = value;
                break;
            case UNW_X86_64_RBX:
                gregs.rbx = value;
                break;
            case UNW_X86_64_RSI:
                gregs.rsi = value;
                break;
            case UNW_X86_64_RDI:
                gregs.rdi = value;
                break;
            case UNW_X86_64_RBP:
                gregs.rbp = value;
                break;
            case UNW_X86_64_RSP:
                gregs.rsp = value;
                break;
            case UNW_X86_64_R8:
                gregs.r8 = value;
                break;
            case UNW_X86_64_R9:
                gregs.r9 = value;
                break;
            case UNW_X86_64_R10:
                gregs.r10 = value;
                break;
            case UNW_X86_64_R11:
                gregs.r11 = value;
                break;
            case UNW_X86_64_R12:
                gregs.r12 = value;
                break;
            case UNW_X86_64_R13:
                gregs.r13 = value;
                break;
            case UNW_X86_64_R14:
                gregs.r14 = value;
                break;
            case UNW_X86_64_R15:
                gregs.r15 = value;
                break;
            case UNW_X86_64_RIP:
                gregs.rip = value;
                break;
            default:
                return false;
        }

        return true;
    }

    bool get_reg(int reg, Float *value) const
    {
        return false;
    }

    bool set_reg(int reg, Float value)
    {
        return false;
    }

    bool get_reg(int reg, Vector *value) const
    {
        return false;
    }

    bool set_reg(int reg, Vector value)
    {
        return false;
    }

    static bool is_greg(int reg)
    {
        return ((unsigned int)reg <= UNW_X86_64_RIP);
    }

    static bool is_freg(int reg)
    {
        return false;
    }

    static bool is_vreg(int reg)
    {
        return false;
    }

    static const char *get_name(int reg)
    {
        switch (reg) {
            case UNW_REG_IP:
                return "rip";
            case UNW_REG_SP:
                return "rsp";
            case UNW_X86_64_RAX:
                return "rax";
            case UNW_X86_64_RDX:
                return "rdx";
            case UNW_X86_64_RCX:
                return "rcx";
            case UNW_X86_64_RBX:
                return "rbx";
            case UNW_X86_64_RSI:
                return "rsi";
            case UNW_X86_64_RDI:
                return "rdi";
            case UNW_X86_64_RBP:
                return "rbp";
            case UNW_X86_64_RSP:
                return "rsp";
            case UNW_X86_64_R8:
                return "r8";
            case UNW_X86_64_R9:
                return "r9";
            case UNW_X86_64_R10:
                return "r10";
            case UNW_X86_64_R11:
                return "r11";
            case UNW_X86_64_R12:
                return "r12";
            case UNW_X86_64_R13:
                return "r13";
            case UNW_X86_64_R14:
                return "r14";
            case UNW_X86_64_R15:
                return "r15";
            case UNW_X86_64_RIP:
                return "rip";
            default:
                return "unknown register";
        }
    }

    void load()
    {
        unw_getcontext((unw_context_t *)this);
    }

    void restore()
    {
        unw_setcontext((unw_context_t *)this);
    }

    Word  get_sp() const
    {
        return gregs.rsp;
    }

    void set_sp(Word value)
    {
        gregs.rsp = value;
    }

    Word  get_ip() const
    {
        return gregs.rip;
    }

    void set_ip(Word value)
    {
        gregs.rip = value;
    }

private:
    struct {
        Word rax;
        Word rbx;
        Word rcx;
        Word rdx;
        Word rdi;
        Word rsi;
        Word rbp;
        Word rsp;
        Word r8;
        Word r9;
        Word r10;
        Word r11;
        Word r12;
        Word r13;
        Word r14;
        Word r15;
        Word rip;
        Word rflags;
        Word cs;
        Word fs;
        Word gs;
    } gregs;
};

# elif defined(__aarch64__)

class Registers
{
public:
    enum { HIGHEST_DWARF_REGISTER = 96 };
    enum {
        IP = UNW_ARM64_PC,
        SP = UNW_ARM64_SP,
    };

    typedef uintptr_t Word;
    typedef double Float;
    typedef Vector128 Vector;

    Registers()
    {}

    bool get_reg(int reg, Word *value) const
    {
        if (static_cast<unsigned int>(reg) <= 32) {
            *value = gregs.x[reg];
        } else {
            switch (reg) {
                case UNW_REG_IP:
                    *value = gregs.pc;
                    break;
                case UNW_REG_SP:
                    *value = gregs.sp;
                    break;
                case UNW_ARM64_RA_SIGN_STATE:
                    *value = gregs.ra_sign_state;
                    break;
                default:
                    return false;
            }
        }

        return true;
    }

    bool set_reg(int reg, Word value)
    {
        if (static_cast<unsigned int>(reg) <= 32) {
            gregs.x[reg] = value;
        } else {
            switch (reg) {
                case UNW_REG_IP:
                    gregs.pc = value;
                    break;
                case UNW_REG_SP:
                    gregs.sp = value;
                    break;
                case UNW_ARM64_RA_SIGN_STATE:
                    gregs.ra_sign_state = value;
                    break;
                default:
                    return false;
            }
        }

        return true;
    }

    bool get_reg(int reg, Float *value) const
    {
        unsigned int i = reg - UNW_ARM64_D0;
        if (i > (UNW_ARM64_D31 - UNW_ARM64_D0))
            return false;

        *value = fregs[i];
        return true;
    }

    bool set_reg(int reg, Float value)
    {
        unsigned int i = reg - UNW_ARM64_D0;
        if (i > (UNW_ARM64_D31 - UNW_ARM64_D0))
            return false;
        fregs[i] = value;
        return true;
    }

    bool get_reg(int reg, Vector *value) const
    {
        return false;
    }

    bool set_reg(int reg, Vector value)
    {
        return false;
    }

    static bool is_greg(int reg)
    {
        return (static_cast<unsigned int>(reg) <= UNW_ARM64_X32) || (reg == UNW_ARM64_RA_SIGN_STATE);
    }

    static bool is_freg(int reg)
    {
        return ((reg >= UNW_ARM64_D0) && (reg <= UNW_ARM64_D31));
    }

    static bool is_vreg(int reg)
    {
        return false;
    }

    static const char *get_name(int reg)
    {
        switch (reg) {
            case UNW_REG_IP:
                return "pc";
            case UNW_REG_SP:
                return "sp";
            case UNW_ARM64_X0:
                return "x0";
            case UNW_ARM64_X1:
                return "x1";
            case UNW_ARM64_X2:
                return "x2";
            case UNW_ARM64_X3:
                return "x3";
            case UNW_ARM64_X4:
                return "x4";
            case UNW_ARM64_X5:
                return "x5";
            case UNW_ARM64_X6:
                return "x6";
            case UNW_ARM64_X7:
                return "x7";
            case UNW_ARM64_X8:
                return "x8";
            case UNW_ARM64_X9:
                return "x9";
            case UNW_ARM64_X10:
                return "x10";
            case UNW_ARM64_X11:
                return "x11";
            case UNW_ARM64_X12:
                return "x12";
            case UNW_ARM64_X13:
                return "x13";
            case UNW_ARM64_X14:
                return "x14";
            case UNW_ARM64_X15:
                return "x15";
            case UNW_ARM64_X16:
                return "x16";
            case UNW_ARM64_X17:
                return "x17";
            case UNW_ARM64_X18:
                return "x18";
            case UNW_ARM64_X19:
                return "x19";
            case UNW_ARM64_X20:
                return "x20";
            case UNW_ARM64_X21:
                return "x21";
            case UNW_ARM64_X22:
                return "x22";
            case UNW_ARM64_X23:
                return "x23";
            case UNW_ARM64_X24:
                return "x24";
            case UNW_ARM64_X25:
                return "x25";
            case UNW_ARM64_X26:
                return "x26";
            case UNW_ARM64_X27:
                return "x27";
            case UNW_ARM64_X28:
                return "x28";
            case UNW_ARM64_X29:
                return "fp";
            case UNW_ARM64_X30:
                return "lr";
            case UNW_ARM64_X31:
                return "sp";
            case UNW_ARM64_X32:
                return "pc";
            case UNW_ARM64_D0:
                return "d0";
            case UNW_ARM64_D1:
                return "d1";
            case UNW_ARM64_D2:
                return "d2";
            case UNW_ARM64_D3:
                return "d3";
            case UNW_ARM64_D4:
                return "d4";
            case UNW_ARM64_D5:
                return "d5";
            case UNW_ARM64_D6:
                return "d6";
            case UNW_ARM64_D7:
                return "d7";
            case UNW_ARM64_D8:
                return "d8";
            case UNW_ARM64_D9:
                return "d9";
            case UNW_ARM64_D10:
                return "d10";
            case UNW_ARM64_D11:
                return "d11";
            case UNW_ARM64_D12:
                return "d12";
            case UNW_ARM64_D13:
                return "d13";
            case UNW_ARM64_D14:
                return "d14";
            case UNW_ARM64_D15:
                return "d15";
            case UNW_ARM64_D16:
                return "d16";
            case UNW_ARM64_D17:
                return "d17";
            case UNW_ARM64_D18:
                return "d18";
            case UNW_ARM64_D19:
                return "d19";
            case UNW_ARM64_D20:
                return "d20";
            case UNW_ARM64_D21:
                return "d21";
            case UNW_ARM64_D22:
                return "d22";
            case UNW_ARM64_D23:
                return "d23";
            case UNW_ARM64_D24:
                return "d24";
            case UNW_ARM64_D25:
                return "d25";
            case UNW_ARM64_D26:
                return "d26";
            case UNW_ARM64_D27:
                return "d27";
            case UNW_ARM64_D28:
                return "d28";
            case UNW_ARM64_D29:
                return "d29";
            case UNW_ARM64_D30:
                return "d30";
            case UNW_ARM64_D31:
                return "d31";
            default:
                return "unknown register";
        }
    }

    void load()
    {
        unw_getcontext((unw_context_t *)this);
    }

    void restore()
    {
        unw_setcontext((unw_context_t *)this);
    }

    Word  get_sp() const
    {
        return gregs.sp;
    }

    void set_sp(Word value)
    {
        gregs.sp = value;
    }

    Word  get_ip() const
    {
        return gregs.pc;
    }

    void set_ip(Word value)
    {
        gregs.pc = value;
    }

private:
    struct {
        Word x[29]; // x0-x28
        Word fp;    // Frame pointer x29
        Word lr;    // Link register x30
        Word sp;    // Stack pointer x31
        Word pc;    // Program counter
        Word ra_sign_state; // RA sign state register
    } gregs;
    Float fregs[32];
};

# elif defined(__powerpc64__)

class Registers
{
public:
    enum { HIGHEST_DWARF_REGISTER = 117 };
    enum {
        IP = UNW_PPC64_PC,
        SP = UNW_PPC64_R1,
    };

    typedef uintptr_t Word;
    typedef double Float;
    typedef Vector128 Vector;

    Registers()
    {}

    bool get_reg(int reg, Word *value) const
    {
        if (static_cast<unsigned int>(reg) <= UNW_PPC64_R31) {
            *value = gregs.r[reg];
        } else {
            switch (reg) {
                case UNW_REG_IP:
                    *value = gregs.pc;
                    break;
                case UNW_REG_SP:
                    *value = gregs.r[1];
                    break;
                case UNW_PPC64_CR0:
                    *value = (gregs.cr & 0xF0000000);
                    break;
                case UNW_PPC64_CR1:
                    *value = (gregs.cr & 0x0F000000);
                    break;
                case UNW_PPC64_CR2:
                    *value = (gregs.cr & 0x00F00000);
                    break;
                case UNW_PPC64_CR3:
                    *value = (gregs.cr & 0x000F0000);
                    break;
                case UNW_PPC64_CR4:
                    *value = (gregs.cr & 0x0000F000);
                    break;
                case UNW_PPC64_CR5:
                    *value = (gregs.cr & 0x00000F00);
                    break;
                case UNW_PPC64_CR6:
                    *value = (gregs.cr & 0x000000F0);
                    break;
                case UNW_PPC64_CR7:
                    *value = (gregs.cr & 0x0000000F);
                    break;
                case UNW_PPC64_XER:
                    *value = gregs.xer;
                    break;
                case UNW_PPC64_LR:
                    *value = gregs.lr;
                    break;
                case UNW_PPC64_CTR:
                    *value = gregs.ctr;
                    break;
                case UNW_PPC64_PC:
                    *value = gregs.pc;
                    break;
                case UNW_PPC64_VRSAVE:
                    *value = gregs.vrsave;
                    break;
                default:
                    return false;
            }
        }

        return true;
    }

    bool set_reg(int reg, Word value)
    {
        if (static_cast<unsigned int>(reg) <= UNW_PPC64_R31) {
            gregs.r[reg] = value;
        } else {
            switch (reg) {
                case UNW_REG_IP:
                    gregs.pc = value;
                    break;
                case UNW_REG_SP:
                    gregs.r[1] = value;
                    break;
                case UNW_PPC64_CR0:
                    gregs.cr &= 0x0FFFFFFF;
                    gregs.cr |= (value & 0xF0000000);
                    break;
                case UNW_PPC64_CR1:
                    gregs.cr &= 0xF0FFFFFF;
                    gregs.cr |= (value & 0x0F000000);
                    break;
                case UNW_PPC64_CR2:
                    gregs.cr &= 0xFF0FFFFF;
                    gregs.cr |= (value & 0x00F00000);
                    break;
                case UNW_PPC64_CR3:
                    gregs.cr &= 0xFFF0FFFF;
                    gregs.cr |= (value & 0x000F0000);
                    break;
                case UNW_PPC64_CR4:
                    gregs.cr &= 0xFFFF0FFF;
                    gregs.cr |= (value & 0x0000F000);
                    break;
                case UNW_PPC64_CR5:
                    gregs.cr &= 0xFFFFF0FF;
                    gregs.cr |= (value & 0x00000F00);
                    break;
                case UNW_PPC64_CR6:
                    gregs.cr &= 0xFFFFFF0F;
                    gregs.cr |= (value & 0x000000F0);
                    break;
                case UNW_PPC64_CR7:
                    gregs.cr &= 0xFFFFFFF0;
                    gregs.cr |= (value & 0x0000000F);
                    break;
                case UNW_PPC64_XER:
                    gregs.xer = value;
                    break;
                case UNW_PPC64_LR:
                    gregs.lr = value;
                    break;
                case UNW_PPC64_CTR:
                    gregs.ctr = value;
                    break;
                case UNW_PPC64_PC:
                    gregs.pc = value;
                    break;
                case UNW_PPC64_VRSAVE:
                    gregs.vrsave = value;
                    break;
                default:
                    return false;
            }
        }

        return true;
    }

    bool get_reg(int reg, Float *value) const
    {
        unsigned int i = reg - UNW_PPC64_F0;
        if (i > (UNW_PPC64_F31 - UNW_PPC64_F0))
            return false;
        *value = vsregs[i].f64;
        return true;
    }

    bool set_reg(int reg, Float value)
    {
        unsigned int i = reg - UNW_PPC64_F0;
        if (i > (UNW_PPC64_F31 - UNW_PPC64_F0))
            return false;
        vsregs[i].f64 = value;
        return true;
    }

    bool get_reg(int reg, Vector *value) const
    {
        unsigned int i = reg - UNW_PPC64_V0;
        if (i > (UNW_PPC64_V31 - UNW_PPC64_V0))
            return false;
        *value = vsregs[i].v128;
        return true;
    }

    bool set_reg(int reg, Vector value)
    {
        unsigned int i = reg - UNW_PPC64_V0;
        if (i > (UNW_PPC64_V31 - UNW_PPC64_V0))
            return false;
        vsregs[i].v128 = value;
        return true;
    }

    static bool is_greg(int reg)
    {
        return (static_cast<unsigned int>(reg) <= UNW_PPC64_R31) || ((reg >= UNW_PPC64_LR) && (reg <= UNW_PPC64_PC)) || ((reg >= UNW_PPC64_CR0) && (reg <= UNW_PPC64_XER));
    }

    static bool is_freg(int reg)
    {
        return ((reg >= UNW_PPC64_F0) && (reg <= UNW_PPC64_F31));
    }

    static bool is_vreg(int reg)
    {
        return ((reg >= UNW_PPC64_V0) && (reg <= UNW_PPC64_V31));
    }

    static const char *get_name(int reg)
    {
        switch (reg) {
            case UNW_REG_IP:
                return "ip";
            case UNW_REG_SP:
                return "sp";
            case UNW_PPC64_R0:
                return "r0";
            case UNW_PPC64_R1:
                return "r1";
            case UNW_PPC64_R2:
                return "r2";
            case UNW_PPC64_R3:
                return "r3";
            case UNW_PPC64_R4:
                return "r4";
            case UNW_PPC64_R5:
                return "r5";
            case UNW_PPC64_R6:
                return "r6";
            case UNW_PPC64_R7:
                return "r7";
            case UNW_PPC64_R8:
                return "r8";
            case UNW_PPC64_R9:
                return "r9";
            case UNW_PPC64_R10:
                return "r10";
            case UNW_PPC64_R11:
                return "r11";
            case UNW_PPC64_R12:
                return "r12";
            case UNW_PPC64_R13:
                return "r13";
            case UNW_PPC64_R14:
                return "r14";
            case UNW_PPC64_R15:
                return "r15";
            case UNW_PPC64_R16:
                return "r16";
            case UNW_PPC64_R17:
                return "r17";
            case UNW_PPC64_R18:
                return "r18";
            case UNW_PPC64_R19:
                return "r19";
            case UNW_PPC64_R20:
                return "r20";
            case UNW_PPC64_R21:
                return "r21";
            case UNW_PPC64_R22:
                return "r22";
            case UNW_PPC64_R23:
                return "r23";
            case UNW_PPC64_R24:
                return "r24";
            case UNW_PPC64_R25:
                return "r25";
            case UNW_PPC64_R26:
                return "r26";
            case UNW_PPC64_R27:
                return "r27";
            case UNW_PPC64_R28:
                return "r28";
            case UNW_PPC64_R29:
                return "r29";
            case UNW_PPC64_R30:
                return "r30";
            case UNW_PPC64_R31:
                return "r31";
            case UNW_PPC64_CR0:
                return "cr0";
            case UNW_PPC64_CR1:
                return "cr1";
            case UNW_PPC64_CR2:
                return "cr2";
            case UNW_PPC64_CR3:
                return "cr3";
            case UNW_PPC64_CR4:
                return "cr4";
            case UNW_PPC64_CR5:
                return "cr5";
            case UNW_PPC64_CR6:
                return "cr6";
            case UNW_PPC64_CR7:
                return "cr7";
            case UNW_PPC64_XER:
                return "xer";
            case UNW_PPC64_LR:
                return "lr";
            case UNW_PPC64_CTR:
                return "ctr";
            case UNW_PPC64_PC:
                return "pc";
            case UNW_PPC64_VRSAVE:
                return "vrsave";
            case UNW_PPC64_F0:
                return "fp0";
            case UNW_PPC64_F1:
                return "fp1";
            case UNW_PPC64_F2:
                return "fp2";
            case UNW_PPC64_F3:
                return "fp3";
            case UNW_PPC64_F4:
                return "fp4";
            case UNW_PPC64_F5:
                return "fp5";
            case UNW_PPC64_F6:
                return "fp6";
            case UNW_PPC64_F7:
                return "fp7";
            case UNW_PPC64_F8:
                return "fp8";
            case UNW_PPC64_F9:
                return "fp9";
            case UNW_PPC64_F10:
                return "fp10";
            case UNW_PPC64_F11:
                return "fp11";
            case UNW_PPC64_F12:
                return "fp12";
            case UNW_PPC64_F13:
                return "fp13";
            case UNW_PPC64_F14:
                return "fp14";
            case UNW_PPC64_F15:
                return "fp15";
            case UNW_PPC64_F16:
                return "fp16";
            case UNW_PPC64_F17:
                return "fp17";
            case UNW_PPC64_F18:
                return "fp18";
            case UNW_PPC64_F19:
                return "fp19";
            case UNW_PPC64_F20:
                return "fp20";
            case UNW_PPC64_F21:
                return "fp21";
            case UNW_PPC64_F22:
                return "fp22";
            case UNW_PPC64_F23:
                return "fp23";
            case UNW_PPC64_F24:
                return "fp24";
            case UNW_PPC64_F25:
                return "fp25";
            case UNW_PPC64_F26:
                return "fp26";
            case UNW_PPC64_F27:
                return "fp27";
            case UNW_PPC64_F28:
                return "fp28";
            case UNW_PPC64_F29:
                return "fp29";
            case UNW_PPC64_F30:
                return "fp30";
            case UNW_PPC64_F31:
                return "fp31";
            case UNW_PPC64_V0:
                return "v0";
            case UNW_PPC64_V1:
                return "v1";
            case UNW_PPC64_V2:
                return "v2";
            case UNW_PPC64_V3:
                return "v3";
            case UNW_PPC64_V4:
                return "v4";
            case UNW_PPC64_V5:
                return "v5";
            case UNW_PPC64_V6:
                return "v6";
            case UNW_PPC64_V7:
                return "v7";
            case UNW_PPC64_V8:
                return "v8";
            case UNW_PPC64_V9:
                return "v9";
            case UNW_PPC64_V10:
                return "v10";
            case UNW_PPC64_V11:
                return "v11";
            case UNW_PPC64_V12:
                return "v12";
            case UNW_PPC64_V13:
                return "v13";
            case UNW_PPC64_V14:
                return "v14";
            case UNW_PPC64_V15:
                return "v15";
            case UNW_PPC64_V16:
                return "v16";
            case UNW_PPC64_V17:
                return "v17";
            case UNW_PPC64_V18:
                return "v18";
            case UNW_PPC64_V19:
                return "v19";
            case UNW_PPC64_V20:
                return "v20";
            case UNW_PPC64_V21:
                return "v21";
            case UNW_PPC64_V22:
                return "v22";
            case UNW_PPC64_V23:
                return "v23";
            case UNW_PPC64_V24:
                return "v24";
            case UNW_PPC64_V25:
                return "v25";
            case UNW_PPC64_V26:
                return "v26";
            case UNW_PPC64_V27:
                return "v27";
            case UNW_PPC64_V28:
                return "v28";
            case UNW_PPC64_V29:
                return "v29";
            case UNW_PPC64_V30:
                return "v30";
            case UNW_PPC64_V31:
                return "v31";
            default:
                return "unknown register";
        }
    }

    void load()
    {
        unw_getcontext((unw_context_t *)this);
    }

    void restore()
    {
        unw_setcontext((unw_context_t *)this);
    }

    Word  get_sp() const
    {
        return gregs.r[1];
    }

    void set_sp(Word value)
    {
        gregs.r[1] = value;
    }

    Word  get_ip() const
    {
        return gregs.pc;
    }

    void set_ip(Word value)
    {
        gregs.pc = value;
    }

private:
    struct {
        Word r[32];
        Word cr;      // Condition register
        Word xer;     // User's integer exception register
        Word lr;      // Link register
        Word ctr;     // Count register
        Word pc;
        Word vrsave;  // Vector Save Register
    } gregs;
    union {
        Float f64;
        Vector v128;
    } vsregs[64];
};

#elif defined(__ppc__)
#  error "Unsupported architecture."
#elif defined(__arm__)
#  error "Unsupported architecture."
#elif defined(__or1k__)
#  error "Unsupported architecture."
#elif defined(__hexagon__)
#  error "Unsupported architecture."
#elif defined(__mips__)
#  if defined(_ABIO32) && _MIPS_SIM == _ABIO32
#    error "Unsupported architecture."
#  elif defined(_ABIN32) && _MIPS_SIM == _ABIN32
#    error "Unsupported architecture."
#  elif defined(_ABI64) && _MIPS_SIM == _ABI64
#    error "Unsupported architecture."
#  else
#    error "Unsupported MIPS ABI and/or environment"
#  endif

#elif defined(__sparc__)
#  error "Unsupported architecture."
#elif defined(__riscv)
#  error "Unsupported architecture."
#elif defined(__ve__)
#  error "Unsupported architecture."
#else
#  error "Unsupported architecture."
#endif

#endif // __REGISTERS_HPP__

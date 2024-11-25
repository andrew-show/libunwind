#ifndef DWARF_PARSER_HPP
#define DWARF_PARSER_HPP

#include <cstdint>
#include <stddef.h>
#include <stdint.h>
#include <memory.h>
#include <libunwind.h>
#include "dwarf2.h"
#include "Registers.hpp"

#define UNW_STEP_SUCCESS 1
#define UNW_STEP_END     0

namespace dwarf {

static inline unsigned int ctz(uint32_t x)
{
    return __builtin_ctz(x);
}

static inline unsigned int ctz(uint64_t x)
{
    return __builtin_ctzll(x);
}

/// dereference integer value from unaligned address
/// @param p pointer to unaligned memory address to be dereferenced
/// @retval the return value is data read from the memory.
template<typename T>
static inline T dereference(const void *p)
{
    return *(T __attribute__((aligned(1))) *)p;
}

/// Read NULL terminated string from DWARF buffer
/// @param result pointer the the buffer to receive the result.
/// @param ptr pointer to the beging of memory block
/// @param end pointer to the end of of memory block
/// @retval the return value is pointer to the end of read data.
static inline const unsigned char *deserialize(const char **result, const unsigned char *ptr, const unsigned char *end)
{
    const unsigned char *p = ptr;
    while (p < end) {
        unsigned char byte = *p++;
        if (!byte) {
            *result = (const char *)ptr;
            return p;
        }
    }

    return nullptr;
}

/// Read integer value from DWARF buffer
template<typename T>
static inline const unsigned char *deserialize(T *result, const unsigned char *ptr, const unsigned char *end)
{
    const unsigned char *p = ptr + sizeof(T);
    if (p > end)
        return nullptr;
    *result = dereference<T>(ptr);
    return p;
}

/// ULEB128 class use to read DWARF ULEB128 data
struct ULEB128
{
    ULEB128() {}
    explicit ULEB128(uint64_t rhs): val(rhs) {}
    ULEB128 &operator=(uint64_t rhs) { val = rhs; return *this; }
    operator uint64_t() const { return val; };
    friend const unsigned char *deserialize(ULEB128 *result, const unsigned char *ptr, const unsigned char *end)
    {
        uint64_t val = 0;

        for (unsigned int offset = 0; ptr < end; offset += 7) {
            unsigned char byte = *ptr++;
            val >>= 7;
            val |= static_cast<uint64_t>(byte) << 57;
            if (offset >= 63) {
                if (byte > 1)
                    break;
            } else if (byte & 0x80) {
                continue;
            }

            result->val = val >> (57 - offset);
            return ptr;
        }

        return nullptr;
    }


private:
    uint64_t val;
};

/// SLEB128 class use to read SLEB128 data
struct SLEB128
{
    SLEB128() {}
    explicit SLEB128(int64_t rhs): val(rhs) {}
    SLEB128 &operator=(int64_t rhs) { val = rhs; return *this; }
    operator int64_t() const { return val; };

    friend const unsigned char *deserialize(SLEB128 *result, const unsigned char *ptr, const unsigned char *end)
    {
        uint64_t val = 0;

        for (unsigned int offset = 0; ptr < end; offset += 7) {
            unsigned char byte = *ptr++;
            val >>= 7;
            val |= static_cast<uint64_t>(byte) << 57;
            if (offset >= 63) {
                if ((byte != 0) && (byte != 0x7f))
                    break;
            } else if (byte & 0x80) {
                continue;
            }

            result->val = static_cast<int64_t>(val) >> (57 - offset);
            return ptr;
        }

        return nullptr;
    }

private:
    int64_t val;
};

/// Macro use to define LEB128 encoded data
#define ULEB128_1(x) (uint8_t)((x) & 0x7f)
#define SLEB128_1(x) (uint8_t)((x) & 0x7f)

#define ULEB128_2(x) (uint8_t)(0x80 | (x)), (uint8_t)((((uint16_t)(x)) >> 7) & 0x7F)
#define SLEB128_2(x) (uint8_t)(0x80 | (x)), (uint8_t)((((int16_t)(x)) >> 7) & 0x7F)

#define ULEB128_3(x) (uint8_t)(0x80 | (x)), (uint8_t)(0x80 | (((uint32_t)(x)) >> 7)), (uint8_t)((((uint32_t)(x)) >> 14) & 0x7F)
#define SLEB128_3(x) (uint8_t)(0x80 | (x)), (uint8_t)(0x80 | (((int32_t)(x)) >> 7)), (uint8_t)((((int32_t)(x)) >> 14) & 0x7F)

#define ULEB128_4(x) (uint8_t)(0x80 | (x)), (uint8_t)(0x80 | (((uint32_t)(x)) >> 7)), (uint8_t)(0x80 | (((uint32_t)(x)) >> 14)), (uint8_t)((((uint32_t)(x)) >> 21) & 0x7F)
#define SLEB128_4(x) (uint8_t)(0x80 | (x)), (uint8_t)(0x80 | (((int32_t)(x)) >> 7)), (uint8_t)(0x80 | (((int32_t)(x)) >> 14)), (uint8_t)((((int32_t)(x)) >> 21) & 0x7F)

/// Length class to read length data of IE
struct Length
{
    Length() {}
    explicit Length(size_t rhs): val(rhs) {}
    Length &operator=(size_t rhs) { val = rhs; return *this; }
    operator size_t() const { return val; };
    friend const unsigned char *deserialize(Length *result, const unsigned char *ptr, const unsigned char *end)
    {
        const unsigned char *p = ptr + sizeof(uint32_t);
        if (p > end)
            return nullptr;
        size_t val = dereference<uint32_t>(ptr);
        if (val == 0xffffffff) {
            ptr = p;
            p += sizeof(uint64_t);
            if (p > end)
                return nullptr;
            val = dereference<uint64_t>(ptr);
        }

        result->val = val;
        return p;
    }

private:
    size_t val;
};

struct Buffer
{
    Buffer(): data(nullptr), size(0)
    {}

    Buffer(const void *data, size_t size): data(data), size(size)
    {}

    operator bool() const { return data != nullptr; }

    void reset()
    {
        data = nullptr;
        size = 0;
    }

    void reset(const void *data, size_t size)
    {
        this->data = data;
        this->size = size;
    }

    const void *data;
    size_t size;
};

/// Read data from DWARF buffer
/// @param result pointer to target buffer to received the result
/// @param ptr pointer to the buffer to be read
/// @param end pointer to the end of buffer
/// @return If the function succeeds, return the pointer
/// after the read bytes; return nullptr to indicate an error.
template<typename T, typename R>
static inline const unsigned char *get(R *result, const unsigned char *ptr, const unsigned char *end)
{
    T val;
    ptr = deserialize(&val, ptr, end);
    if (!ptr)
        return nullptr;
    *result = val;
    return ptr;
}

/// DW_FORM_block
/// FORM<uint8_t>, FORM<uint16_t>, FORM<uint32_t>, FORM<ULEB128> 
template<typename T>
struct FORM
{
public:
    operator Buffer() const
    {
        size_t size = 0;
        const unsigned char *data = get<T>(&size, buf, (const unsigned char *)UINTPTR_MAX);
        return Buffer(data, size);
    }

    friend const unsigned char *deserialize(FORM<T> *result, const unsigned char *ptr, const unsigned char *end)
    {
        size_t size;
        const unsigned char *p = get<T>(&size, ptr, end);
        if (!p)
            return nullptr;
        p += size;
        if (p > end)
            return nullptr;
        result->buf = ptr;
        return p;
    }

private:
    const unsigned char *buf;
};

enum class Origin
{
    BEGIN,
    RELATIVE,
    END,
};

/// @brief Parse use to read data from dwarf buffer.
class Parser
{
public:
    Parser(const void *buf, size_t size, uintptr_t dbase = 0, uintptr_t tbase = 0, uintptr_t fbase = 0):
        begin((const unsigned char *)buf),
        end((const unsigned char *)buf + size),
        ptr((const unsigned char *)buf),
        dbase(dbase),
        tbase(tbase),
        fbase(fbase)
    {}

    template<typename T, typename R>
    bool get(R *result)
    {
        const unsigned char *p = dwarf::get<T>(result, ptr, end);
        if (!p)
            return false;
        ptr = p;
        return true;
    }

    template<typename T>
    bool get(T *result, uint8_t encoding)
    {
        uintptr_t val;
        if (!deserialize(&val, encoding))
            return false;
        *result = (T)val;
        return true;
    }

    size_t tell() const
    {
        return ptr - begin;
    }

    bool seek(ptrdiff_t offset, Origin origin)
    {
        size_t position;
        switch (origin) {
            case Origin::BEGIN:
                position = 0;
                break;
            case Origin::RELATIVE:
                position = ptr - begin;
                break;
            case Origin::END:
                position = end - begin;
                break;
            default:
                return false;
        }

        position += offset;
        size_t size = end - begin;
        if (position > size)
            return false;
        ptr = begin + offset;
        return true;
    }
        
    const unsigned char *cursor() const
    {
        return ptr;
    }

    size_t remaining_bytes() const
    {
        return end - ptr;
    }

    void remaining_bytes(size_t size)
    {
        end = ptr + size;
    }

private:
    bool deserialize(uintptr_t *result, uint8_t encoding)
    {
        uintptr_t base;

        switch (encoding & 0x70) {
            case DW_EH_PE_aligned:
            case DW_EH_PE_absptr:
                base = 0;
                break;
            case DW_EH_PE_pcrel:
                base = (uintptr_t)ptr;
                break;
            case DW_EH_PE_textrel:
                if (!tbase)
                    return false;
                base = tbase;
                break;
            case DW_EH_PE_datarel:
                if (!dbase)
                    return false;
                base = dbase;
                break;
            case DW_EH_PE_funcrel:
                if (!fbase)
                    return false;
                base = fbase;
                break;
            default:
                // unknown pointer encoding
                return false;
        }

        uintptr_t val;
        switch (encoding & 0x0F) {
            case DW_EH_PE_ptr:
                if (!get<uintptr_t>(&val))
                    return false;
                break;
            case DW_EH_PE_uleb128:
                if (!get<ULEB128>(&val))
                    return false;
                break;
            case DW_EH_PE_udata2:
                if (!get<uint16_t>(&val))
                    return false;
                break;
            case DW_EH_PE_udata4:
                if (!get<uint32_t>(&val))
                    return false;
                break;
            case DW_EH_PE_udata8:
                if (!get<uint64_t>(&val))
                    return false;
                break;
            case DW_EH_PE_sleb128:
                if (!get<SLEB128>(&val))
                    return false;
                break;
            case DW_EH_PE_sdata2:
                if (!get<int16_t>(&val))
                    return false;
                break;
            case DW_EH_PE_sdata4:
                if (!get<int32_t>(&val))
                    return false;
                break;
            case DW_EH_PE_sdata8:
                if (!get<int64_t>(&val))
                    return false;
                break;
            default:
                return false;
        }

        val += base;
        if ((encoding & 0x70) == DW_EH_PE_aligned)
            val &= ~(sizeof(void *) - 1); // align to address size
        if (encoding & DW_EH_PE_indirect)
            val = dereference<uintptr_t>((const void *)val);

        *result = val;
        return true;
    }

    const unsigned char *begin;
    const unsigned char *end;
    const unsigned char *ptr;
    uintptr_t dbase;
    uintptr_t tbase;
    uintptr_t fbase;
};

struct eh_frame_hdr
{
    uint8_t version;
    uint8_t eh_frame_ptr_enc;
    uint8_t fde_count_enc;
    uint8_t table_enc;
};

struct eh_frame
{};

// Use to declare pseudo signal .eh_frame_hdr and .eh_frame
#define SIGNAL_EH_FRAME_DECLARE(name, return_address_register, ...) \
    struct { \
        struct { \
            uint8_t version; \
            uint8_t eh_frame_ptr_enc; \
            uint8_t fde_count_enc; \
            uint8_t table_enc; \
            uint16_t eh_frame_ptr; \
            uint16_t fde_count; \
            uintptr_t location; \
            const void *fde; \
        } eh_frame_hdr; \
        struct { \
            struct { \
                uint32_t length; \
                uint32_t id; \
                uint8_t version; \
                char augmentation[4]; \
                uint8_t code_align; \
                int8_t data_align; \
                uint8_t ra_register; \
                uint8_t aug_size; \
                uint8_t fde_encoding; \
                unsigned char instructions[1]; \
                unsigned char padding[5]; \
            } cie; \
            struct { \
                uint32_t length; \
                uint32_t cie_pointer; \
                uintptr_t location; \
                uintptr_t address_range; \
                uint8_t aug_size; \
                unsigned char instructions[sizeof((int[]) __VA_ARGS__ )/sizeof(int)]; \
            } fde; \
        } eh_frame; \
    } name = { \
        { \
            1, DW_EH_PE_pcrel | DW_EH_PE_udata2, DW_EH_PE_udata2, DW_EH_PE_ptr, \
            sizeof(name.eh_frame_hdr) - 4, \
            1, \
            0, \
            &name.eh_frame.fde, \
        }, \
        { \
            { sizeof(name.eh_frame.cie) - sizeof(name.eh_frame.cie.length) - sizeof(name.eh_frame.cie.padding), \
              0, 1, "zRS", ULEB128_1(1), SLEB128_1(-8), \
              return_address_register, 1, DW_EH_PE_ptr, { DW_CFA_nop } }, \
            { sizeof(name.eh_frame.fde) - 4, sizeof(name.eh_frame.cie) + sizeof(uint32_t), 0, 0, 0, __VA_ARGS__ } \
        } \
    };

#define SIGNAL_EH_FRAME_SET_LOCATION(name, address, range)  \
    do { \
        name.eh_frame_hdr.location = name.eh_frame.fde.location = (uintptr_t)(address); \
        name.eh_frame.fde.address_range = (uintptr_t)(range); \
    } while (false);

/// @brief Unwind parameters for stack unwinding.
struct UnwindInfo
{
    UnwindInfo(uintptr_t ra, bool signal_frame):
        ra(ra), tbase(0), dbase(0), eh_frame_hdr(0), eh_frame_hdr_size(0), signal_frame(signal_frame ? 1 : 0)
    {}

    operator bool() const
    {
        return eh_frame_hdr != 0;
    }

    uintptr_t ra;                       ///< return address.
    uintptr_t tbase;                    ///< text base.
    uintptr_t dbase;                    ///< data base.
    struct eh_frame_hdr *eh_frame_hdr;  ///< address of .eh_frame_hdr section.
    size_t eh_frame_hdr_size;           ///< size of .eh_frame_hdr section.
    unsigned int signal_frame:1;        ///< non-zero for signal frame.
};

/// @brief CIE parser.
class CIE
{
public:
    CIE(): address(nullptr)
    {}

    /// Parse CIE.
    /// @param unwind_info unwind relative parameters.
    /// @param buf pointer to the dwarf encoded CIE data.
    /// @param size size of buffer that hold the CIE data.
    /// @retval if the function succeeds, returns UNW_SUCCESS. 
    int parse(const UnwindInfo &unwind_info, const void *buf, size_t size);
    int parse(const UnwindInfo &unwind_info, const void *buf);

    const void *address;
    size_t length;

    struct {
        uint8_t z:1;
        uint8_t P:1;
        uint8_t L:1;
        uint8_t R:1;
        uint8_t S:1;
        uint8_t B:1;
    } augmentation;

    uint8_t lsda_encoding;
    uint8_t fde_encoding;

    int32_t code_align;
    int32_t data_align;
    uint32_t ra_register;
    uintptr_t personality;
    Buffer instructions;
};

inline int CIE::parse(const UnwindInfo &unwind_info, const void *buf, size_t size)
{
    Parser parser(buf, size, unwind_info.dbase, unwind_info.tbase);

    memset(this, 0, sizeof(*this));
    if (!parser.get<Length>(&this->length))
        return UNW_EINVAL;

    if (this->length > parser.remaining_bytes())
        return UNW_EINVAL;

    if (!this->length)
        return UNW_ENOINFO;  // The terminator

    parser.remaining_bytes(this->length);
    this->length += parser.tell();

    uint32_t id;
    if (!parser.get<uint32_t>(&id) || (id != 0))
        return UNW_EINVAL;

    uint8_t version;
    if (!parser.get<uint8_t>(&version))
        return UNW_EINVAL;

    if ((version != 1) && (version != 3))
        return UNW_EBADVERSION;

    const char *aug;
    if (!parser.get<const char *>(&aug))
        return UNW_EINVAL;

    if ((aug[0] == 'e') && (aug[1] == 'h')) {
        uintptr_t eh_ptr;
        if (!parser.get<uintptr_t>(&eh_ptr))
            return UNW_EINVAL;
        aug += 2;
    }

    if (!parser.get<ULEB128>(&this->code_align))
        return UNW_EINVAL;
    if (!parser.get<SLEB128>(&this->data_align))
        return UNW_EINVAL;

    if (version == 1) {
        if (!parser.get<uint8_t>(&ra_register))
            return UNW_EINVAL;
    } else {
        if (!parser.get<ULEB128>(&ra_register))
            return UNW_EINVAL;
    }

    this->lsda_encoding = DW_EH_PE_omit;
    if (*aug == 'z') {
        this->augmentation.z = 1;
        size_t aug_len;
        if (!parser.get<ULEB128>(&aug_len))
            return UNW_EINVAL;
        ++aug;

        while (*aug) {
            switch (*aug) {
                case 'P': {
                    this->augmentation.P = 1;
                    uint8_t personality_encoding;
                    if (!parser.get<uint8_t>(&personality_encoding))
                        return UNW_EINVAL;
                    if (!parser.get(&this->personality, personality_encoding))
                        return UNW_EINVAL;
                    break;
                }
                case 'L':
                    this->augmentation.L = 1;
                    if (!parser.get<uint8_t>(&this->lsda_encoding))
                        return UNW_EINVAL;
                    break;
                case 'R':
                    this->augmentation.R = 1;
                    if (!parser.get<uint8_t>(&this->fde_encoding))
                        return UNW_EINVAL;
                    break;
                case 'S':
                    this->augmentation.S = 1;
                    break;
                case 'B':
                    this->augmentation.B = 1;
                    break;
            }

            ++aug;
        }
    }

    this->instructions.reset(parser.cursor(), parser.remaining_bytes());
    this->address = buf;

    return UNW_ESUCCESS;
}

inline int CIE::parse(const UnwindInfo &unwind_info, const void *buf)
{
    return parse(unwind_info, buf, SIZE_MAX - (size_t)buf);
}

/// @brief FDE parser.
class FDE
{
public:
    FDE(): address(nullptr)
    {}

    /// Parse FDE.
    /// @param unwind_info Unwind parameters.
    /// @param buf pointer to the dwarf encoded FDE data.
    /// @param size size of buffer that hold the FDE data.
    /// @retval if the function succeeds, the return value is UNW_SUCCESS.
    int parse(const UnwindInfo &unwind_info, CIE &cie, const void *buf, size_t size);
    int parse(const UnwindInfo &unwind_info, CIE &cie, const void *buf);

    const void *address;
    size_t length;
    uintptr_t location;
    uintptr_t address_range;
    uintptr_t lsda;
    Buffer instructions;
};

inline int FDE::parse(const UnwindInfo &unwind_info, CIE &cie, const void *buf, size_t size)
{
    Parser parser(buf, size, unwind_info.dbase, unwind_info.tbase);

    memset(this, 0, sizeof(*this));
    if (!parser.get<Length>(&this->length))
        return UNW_EINVAL;

    if (this->length > parser.remaining_bytes())
        return UNW_EINVAL;

    parser.remaining_bytes(this->length);
    this->length += parser.tell();

    uint32_t cie_pointer;
    if (!parser.get<uint32_t>(&cie_pointer))
        return UNW_EINVAL;

    if (cie_pointer == 0)
        return UNW_ENOINFO;  // Return the specific error code

    cie_pointer += 4;  // include the 4 bytes CIE pointer field

    const void *cie_address = parser.cursor() - cie_pointer;
    if (cie_address != cie.address) {
        int ret = cie.parse(unwind_info, cie_address);
        if (ret != UNW_ESUCCESS)
            return ret != UNW_ENOINFO ? ret : UNW_EINVAL;
    }

    if (!parser.get(&this->location, cie.fde_encoding))
        return UNW_EINVAL;

    if (!parser.get(&this->address_range, cie.fde_encoding & 0x0F))
        return UNW_EINVAL;
    if (cie.augmentation.z) {
        uint32_t aug_size;
        if (!parser.get<ULEB128>(&aug_size))
            return UNW_EINVAL;
        size_t aug_offset = parser.tell();
        if (cie.lsda_encoding != DW_EH_PE_omit) {
            if (!parser.get(&this->lsda, cie.lsda_encoding))
                return UNW_EINVAL;
        }

        if (!parser.seek(aug_offset + aug_size, Origin::BEGIN))
            return UNW_EINVAL;
    }

    // parser dwarf instructions
    this->instructions.reset(parser.cursor(), parser.remaining_bytes());
    this->address = buf;
    return UNW_ESUCCESS;
}

inline int FDE::parse(const UnwindInfo &unwind_info, CIE &cie, const void *buf)
{
    return parse(unwind_info, cie, buf, SIZE_MAX - (size_t)buf);
}

/// @brief Class use to execute dwarf expression.
class Expression
{
public:
    Expression(const void *instructions, size_t length):
        instructions(instructions),
        length(length)
    {}

    /// Execute dwarf expression.
    /// @param result pointer to buffer that receive the result.
    /// @param regs registers set that use as context of the expression.
    /// @retval if the function succeeds, the return value is UNW_SUCCESS.
    int operator()(uintptr_t *result, const Registers &regs)
    {
        Stack stack;
        const unsigned char *ptr = (const unsigned char *)instructions;
        const unsigned char *end = (const unsigned char *)instructions + length;
        for ( ; ; ) {
            uint8_t op;
            if (!(ptr = get<uint8_t>(&op, ptr, end)))
                break; // done

            switch (op) {
                case DW_OP_addr: {
                    uintptr_t val;
                    if (!(ptr = get<uintptr_t>(&val, ptr, end)))
                        return UNW_EINVAL;

                    stack.push(val);
                    break;
                }
                case DW_OP_deref:
                    stack.deref();
                    break;
                case DW_OP_const1u: {
                    uint8_t val;
                    if (!(ptr = get<uint8_t>(&val, ptr, end)))
                        return UNW_EINVAL;
                    stack.push(val);
                    break;
                }
                case DW_OP_const1s: {
                    int8_t val;
                    if (!(ptr = get<int8_t>(&val, ptr, end)))
                        return UNW_EINVAL;
                    stack.push(val);
                    break;
                }
                case DW_OP_const2u: {
                    uint16_t val;
                    if (!(ptr = get<uint16_t>(&val, ptr, end)))
                        return UNW_EINVAL;
                    stack.push(val);
                    break;
                }
                case DW_OP_const2s: {
                    int16_t val;
                    if (!(ptr = get<int16_t>(&val, ptr, end)))
                        return UNW_EINVAL;
                    stack.push(val);
                    break;
                }
                case DW_OP_const4u: {
                    uint32_t val;
                    if (!(ptr = get<uint32_t>(&val, ptr, end)))
                        return UNW_EINVAL;
                    stack.push(val);
                    break;
                }
                case DW_OP_const4s: {
                    int32_t val;
                    if (!(ptr = get<int32_t>(&val, ptr, end)))
                        return UNW_EINVAL;
                    stack.push(val);
                    break;
                }
                case DW_OP_const8u: {
                    uint64_t val;
                    if (!(ptr = get<uint64_t>(&val, ptr, end)))
                        return UNW_EINVAL;
                    stack.push(val);
                    break;
                }
                case DW_OP_const8s: {
                    int64_t val;
                    if (!(ptr = get<int64_t>(&val, ptr, end)))
                        return UNW_EINVAL;
                    stack.push(val);
                    break;
                }
                case DW_OP_constu: {
                    uint64_t val;
                    if (!(ptr = get<ULEB128>(&val, ptr, end)))
                        return UNW_EINVAL;
                    stack.push(val);
                    break;
                }
                case DW_OP_consts: {
                    int64_t val;
                    if (!(ptr = get<SLEB128>(&val, ptr, end)))
                        return UNW_EINVAL;
                    stack.push(val);
                    break;
                }
                case DW_OP_dup:
                    stack.dup();
                    break;
                case DW_OP_drop:
                    stack.drop();
                    break;
                case DW_OP_over:
                    stack.over();
                    break;
                case DW_OP_pick: {
                    uint8_t index;
                    if (!(ptr = get<uint8_t>(&index, ptr, end)))
                        return UNW_EINVAL;
                    stack.pick(index);
                    break;
                }
                case DW_OP_swap:
                    stack.swap();
                    break;
                case DW_OP_rot:
                    stack.rot();
                    break;
                case DW_OP_xderef:
                    break;
                case DW_OP_abs:
                    stack.abs();
                    break;
                case DW_OP_and:
                    stack.bitwise_and();
                    break;
                case DW_OP_div:
                    stack.div();
                    break;
                case DW_OP_minus:
                    stack.minus();
                    break;
                case DW_OP_mod:
                    stack.mod();
                    break;
                case DW_OP_mul:
                    stack.mul();
                    break;
                case DW_OP_neg:
                    stack.neg();
                    break;
                case DW_OP_not:
                    stack.bitwise_not();
                    break;
                case DW_OP_or:
                    stack.bitwise_or();
                    break;
                case DW_OP_plus:
                    stack.plus();
                    break;
                case DW_OP_plus_uconst: {
                    uint64_t val;
                    if (!(ptr = get<ULEB128>(&val, ptr, end)))
                        return UNW_EINVAL;
                    stack.plus_uconst(val);
                    break;
                }
                case DW_OP_shl:
                    stack.shl();
                    break;
                case DW_OP_shr:
                    stack.shr();
                    break;
                case DW_OP_shra:
                    stack.shra();
                    break;
                case DW_OP_xor:
                    stack.bitwise_xor();
                    break;
                case DW_OP_skip: {
                    ptrdiff_t offset;
                    if (!(ptr = get<int16_t>(&offset, ptr, end)))
                        return UNW_EINVAL;
                    // The pointer may move before the begining of
                    // instructions, but it's needed in some special case,
                    // at least the DWARF instructions of
                    // __kernel_sigtramp_rt64 in powerpc64 need it.
                    ptr += offset;
                    break;
                }
                case DW_OP_bra: {
                    ptrdiff_t offset;
                    if (!(ptr = get<int16_t>(&offset, ptr, end)))
                        return UNW_EINVAL;
                    if (stack.pop())
                        ptr += offset;
                    break;
                }
                case DW_OP_eq:
                    stack.eq();
                    break;
                case DW_OP_ge:
                    stack.ge();
                    break;
                case DW_OP_gt:
                    stack.gt();
                    break;
                case DW_OP_le:
                    stack.le();
                    break;
                case DW_OP_lt:
                    stack.lt();
                    break;
                case DW_OP_ne:
                    stack.ne();
                    break;
                case DW_OP_lit0:
                case DW_OP_lit1:
                case DW_OP_lit2:
                case DW_OP_lit3:
                case DW_OP_lit4:
                case DW_OP_lit5:
                case DW_OP_lit6:
                case DW_OP_lit7:
                case DW_OP_lit8:
                case DW_OP_lit9:
                case DW_OP_lit10:
                case DW_OP_lit11:
                case DW_OP_lit12:
                case DW_OP_lit13:
                case DW_OP_lit14:
                case DW_OP_lit15:
                case DW_OP_lit16:
                case DW_OP_lit17:
                case DW_OP_lit18:
                case DW_OP_lit19:
                case DW_OP_lit20:
                case DW_OP_lit21:
                case DW_OP_lit22:
                case DW_OP_lit23:
                case DW_OP_lit24:
                case DW_OP_lit25:
                case DW_OP_lit26:
                case DW_OP_lit27:
                case DW_OP_lit28:
                case DW_OP_lit29:
                case DW_OP_lit30:
                case DW_OP_lit31:
                    stack.push(op - DW_OP_lit0);
                    break;
                case DW_OP_reg0:
                case DW_OP_reg1:
                case DW_OP_reg2:
                case DW_OP_reg3:
                case DW_OP_reg4:
                case DW_OP_reg5:
                case DW_OP_reg6:
                case DW_OP_reg7:
                case DW_OP_reg8:
                case DW_OP_reg9:
                case DW_OP_reg10:
                case DW_OP_reg11:
                case DW_OP_reg12:
                case DW_OP_reg13:
                case DW_OP_reg14:
                case DW_OP_reg15:
                case DW_OP_reg16:
                case DW_OP_reg17:
                case DW_OP_reg18:
                case DW_OP_reg19:
                case DW_OP_reg20:
                case DW_OP_reg21:
                case DW_OP_reg22:
                case DW_OP_reg23:
                case DW_OP_reg24:
                case DW_OP_reg25:
                case DW_OP_reg26:
                case DW_OP_reg27:
                case DW_OP_reg28:
                case DW_OP_reg29:
                case DW_OP_reg30:
                case DW_OP_reg31: {
                    typename Registers::Word val;
                    if (!regs.get_reg(op - DW_OP_reg0, &val))
                        return UNW_EBADREG;
                    stack.push(val);
                    break;
                }
                case DW_OP_breg0:
                case DW_OP_breg1:
                case DW_OP_breg2:
                case DW_OP_breg3:
                case DW_OP_breg4:
                case DW_OP_breg5:
                case DW_OP_breg6:
                case DW_OP_breg7:
                case DW_OP_breg8:
                case DW_OP_breg9:
                case DW_OP_breg10:
                case DW_OP_breg11:
                case DW_OP_breg12:
                case DW_OP_breg13:
                case DW_OP_breg14:
                case DW_OP_breg15:
                case DW_OP_breg16:
                case DW_OP_breg17:
                case DW_OP_breg18:
                case DW_OP_breg19:
                case DW_OP_breg20:
                case DW_OP_breg21:
                case DW_OP_breg22:
                case DW_OP_breg23:
                case DW_OP_breg24:
                case DW_OP_breg25:
                case DW_OP_breg26:
                case DW_OP_breg27:
                case DW_OP_breg28:
                case DW_OP_breg29:
                case DW_OP_breg30:
                case DW_OP_breg31: {
                    unsigned int reg = op - DW_OP_breg0;
                    typename Registers::Word base;
                    if (!regs.get_reg(reg, &base))
                        return UNW_EBADREG;
                    intptr_t offset;
                    if (!(ptr = get<SLEB128>(&offset, ptr, end)))
                        return UNW_EINVAL;
                    stack.push(base + offset);
                    break;
                }
                case DW_OP_regx: {
                    unsigned int reg;
                    if (!(ptr = get<ULEB128>(&reg, ptr, end)))
                        return UNW_EINVAL;
                    typename Registers::Word val;
                    if (!regs.get_reg(reg, &val))
                        return UNW_EBADREG;
                    stack.push(val);
                    break;
                }
                case DW_OP_bregx: { 
                    unsigned int reg;
                    if (!(ptr = get<ULEB128>(&reg, ptr, end)))
                        return UNW_EINVAL;
                    typename Registers::Word base;
                    if (!regs.get_reg(reg, &base))
                        return UNW_EBADREG;
                    intptr_t offset;
                    if (!(ptr = get<SLEB128>(&offset, ptr, end)))
                        return UNW_EINVAL;
                    stack.push(base + offset);
                    break;
                }
                case DW_OP_deref_size: {
                    uint8_t size;
                    if (!(ptr = get<uint8_t>(&size, ptr, end)))
                        return UNW_EINVAL;
                    if (!stack.deref_size(size))
                        return UNW_EINVAL;
                    break;
                }
                case DW_OP_nop:
                    break;
                case DW_OP_fbreg:
                case DW_OP_piece:
                case DW_OP_xderef_size:
                case DW_OP_push_object_addres:
                case DW_OP_call2:
                case DW_OP_call4:
                case DW_OP_call_ref:
                case DW_OP_lo_user:
                case DW_OP_APPLE_uninit:
                case DW_OP_hi_user:
                default:
                    return UNW_EINVAL;
            }
        }

        *result = stack.top();
        return UNW_ESUCCESS;
    }

private:
    class Stack
    {
    public:
        enum { Size = 128 };

        Stack(): sp(memory + Size)
        {}

        intptr_t top()
        {
            return sp[0];
        }

        void push(intptr_t val)
        {
            --sp;
            sp[0] = val;
        }

        intptr_t pop()
        {
            ++sp;
            return sp[-1];
        }

        void dup()
        {
            --sp;
            sp[0] = sp[1];
        }

        void drop()
        {
            ++sp;
        }

        void pick(unsigned int index)
        {
            sp[-1] = sp[index];
            --sp;
        }

        void over()
        {
            --sp;
            sp[0] = sp[2];
        }

        void swap()
        {
            intptr_t value;

            value = sp[0];
            sp[0] = sp[1];
            sp[1] = value;
        }

        void rot()
        {
            sp[0] = sp[2];
            sp[1] = sp[0];
            sp[2] = sp[1];
        }

        void deref()
        {
            sp[0] = dereference<intptr_t>((const void *)sp[0]);
        }

        bool deref_size(size_t size)
        {
            switch (size) {
                case 1:
                    sp[0] = dereference<int8_t>((const void *)sp[0]);
                    break;
                case 2:
                    sp[0] = dereference<int16_t>((const void *)sp[0]);
                    break;
                case 4:
                    sp[0] = dereference<int32_t>((const void *)sp[0]);
                    break;
                case 8:
                    sp[0] = dereference<int64_t>((const void *)sp[0]);
                    break;
                default:
                    return false;
            }

            return true;
        }

        void abs()
        {
            if (sp[0] < 0)
                sp[0] = -sp[0];
        }

        void div()
        {
            sp[1] /= sp[0];
            ++sp;
        }

        void minus()
        {
            sp[1] -= sp[0];
            ++sp;
        }

        void mod()
        {
            sp[1] %= sp[0];
            ++sp;
        }

        void mul()
        {
            sp[1] *= sp[0];
            ++sp;
        }

        void neg()
        {
            sp[0] = -sp[0];
        }

        void plus()
        {
            sp[1] += sp[0];
            ++sp;
        }

        void plus_uconst(intptr_t val)
        {
            sp[0] += val;
        }

        void shl()
        {
            sp[1] <<= sp[0];
            ++sp;
        }

        void shr()
        {
            
            (uintptr_t &)sp[1] >>= ((uintptr_t)sp[1]) >> sp[0];
            ++sp;
        }

        void shra()
        {
            sp[1] >>= sp[0];
            ++sp;            
        }

        void bitwise_and()
        {
            sp[1] &= sp[0];
            ++sp;
        }

        void bitwise_not()
        {
            sp[0] = ~sp[0];
        }

        void bitwise_or()
        {
            sp[1] |= sp[0];
            ++sp;
        }

        void bitwise_xor()
        {
            sp[1] >>= sp[0];
            ++sp;
        }

        void le()
        {
            sp[1] = (sp[1] <= sp[0] ? 1 : 0);
            ++sp;
        }

        void ge()
        {
            sp[1] = (sp[1] >= sp[0] ? 1 : 0);
            ++sp;
        }

        void eq()
        {
            sp[1] = (sp[1] == sp[0] ? 1 : 0);
            ++sp;
        }

        void lt()
        {
            sp[1] = (sp[1] < sp[0] ? 1 : 0);
            ++sp;
        }

        void gt()
        {
            sp[1] = (sp[1] > sp[0] ? 1 : 0);
            ++sp;
        }

        void ne()
        {
            sp[1] = (sp[1] != sp[0] ? 1 : 0);
            ++sp;
        }

        intptr_t *sp;
        intptr_t memory[Size];
    };

    const void *instructions;
    size_t length;
};

/// @brief Object stack. 
template<typename T>
class Stack
{
public:
    struct Element: public T
    {
        Element *next;
    };

    Stack(): top(0), recycle(0)
    {}

    /// Allocate an element from pool.
    Element *allocate()
    {
        if (!recycle)
            return 0;
        Element *p = recycle;
        recycle = p->next;
        return p;
    }

    /// Release an element to pool.
    void release(Element *p)
    {
        p->next = recycle;
        recycle = p;
    }

    /// Push one element to stack.
    void push(Element *p)
    {
        p->next = top;
        top = p;
    }

    /// Pop one element from stack.
    Element *pop()
    {
        Element *p = top;
        if (!p)
            return 0;

        top = p->next;
        return p;
    }

private:
    Element *top;
    Element *recycle;
};

/// @brief CFI parser.
class CFI
{
public:
    enum { HIGHEST_DWARF_REGISTER = Registers::HIGHEST_DWARF_REGISTER, };

    CFI()
    {}

    /// Get registers by CFI rules.
    int get(Registers &regs) const
    {
        int ret;
        typename Registers::Word cfa;

        ret = xcfa.get(&cfa, regs);
        if (ret != UNW_ESUCCESS)
            return ret;

        ret = xregs.get(regs, cfa);
        if (ret != UNW_ESUCCESS)
            return ret;

        regs.set_sp(cfa);
        if (!xregs.get_modified(Registers::IP)) {
            typename Registers::Word ra;
            regs.get_reg(cie.ra_register, &ra);

#if defined(__aarch64__)
            if (xregs[UNW_ARM64_RA_SIGN_STATE].aarch64_ra_sign_state()) {
                // These are the autia1716/autib1716 instructions. The hint instructions
                // are used here as gcc does not assemble autia1716/autib1716 for pre
                // armv8.3a targets.
                if (cie.augmentation.B)
                    asm("mov x17, %0;"
                        "mov x16, %1;"
                        "hint 0xe;" // autib1716
                        "mov %0, x17" :
                        "+r"(ra) :
                        "r"(cfa) :
                        "x16", "x17");
                else
                    asm("mov x17, %0;"
                        "mov x16, %1;"
                        "hint 0xc;" // autia1716
                        "mov %0, x17" :
                        "+r"(ra) :
                        "r"(cfa) :
                        "x16", "x17");
            }
#endif // defined(__aarch64__)

            regs.set_ip(ra);
        }

        return UNW_ESUCCESS;
    }

    /// Get procedure information.
    int get_proc_info(unw_proc_info_t *info)
    {
        info->start_ip = fde.location;
        info->end_ip = fde.location + fde.address_range;
        info->lsda = fde.lsda;
        info->handler = cie.personality;
        info->gp = args_size;
        info->flags = 0;
        info->format = 0;
        info->unwind_info = (uintptr_t)fde.address;
        info->unwind_info_size = fde.length;
        info->extra = 0;
        return UNW_ESUCCESS;
    }

    /// Determine if current frame is signal frame.
    bool is_signal_frame() const
    {
        return cie.augmentation.S != 0;
    }

    /// Parse CFI information.
    int parse(const UnwindInfo &unwind_info)
    {
        args_size = 0;

        xcfa.reset();
        xregs.reset();

        if (!unwind_info)
            return UNW_ENOINFO;
        return parse(unwind_info, unwind_info.eh_frame_hdr, unwind_info.eh_frame_hdr_size);
    }

private:
    class XCFA
    {
    public:
        enum {
            def_cfa_null = 0,
            def_cfa,
            def_cfa_expression,
        };

        void reset()
        {
            type = def_cfa_null;
        }

        void cfa(unsigned int reg, ptrdiff_t offset)
        {
            type = def_cfa;
            args.cfa.reg = reg;
            args.cfa.offset = offset;
        }

        bool cfa_offset(ptrdiff_t offset)
        {
            if (type != def_cfa)
                return false;
            args.cfa.offset = offset;
            return true;
        }

        bool cfa_register(unsigned int reg)
        {
            if (type != def_cfa)
                return false;
            args.cfa.reg = reg;
            return true;
        }

        void cfa_expression(FORM<ULEB128> expression)
        {
            type = def_cfa_expression;
            args.expression = expression;
        }

        int get(typename Registers::Word *result, const Registers &regs) const
        {
            switch (type) {
                case def_cfa:
                    if (!regs.get_reg(args.cfa.reg, result))
                        return UNW_EBADREG;

                    *result += args.cfa.offset;
                    break;
                case def_cfa_expression: {
                    Buffer buf = args.expression;
                    Expression expression(buf.data, buf.size);
                    uintptr_t val;
                    int ret = expression(&val, regs);
                    if (ret != UNW_ESUCCESS)
                        return ret;

                    *result = val;
                    break;
                }
                case def_cfa_null:
                default:
                    return UNW_EINVAL;
            }

            return UNW_ESUCCESS;
        }

    private:
        int type;
        union {
            struct {
                uint32_t reg;
                ptrdiff_t offset;
            } cfa; // DW_CFA_def_cfa, DW_CFA_def_cfa_sf, DW_CFA_def_cfa_offset, DW_CFA_def_cfa_offset_sf, DW_CFA_def_cfa_register
            FORM<ULEB128> expression; // DW_CFA_def_cfa_expression,
        } args;
    };

    class XRegister
    {
    public:
        enum {
            CFA_offset = 0,
            CFA_val_offset,
            CFA_expression,
            CFA_val_expression,
            CFA_register,
            CFA_val,
        };

        void cfa_offset(ptrdiff_t offset)
        {
            type = CFA_offset;
            args.offset = offset;
        }

        void cfa_val_offset(ptrdiff_t offset)
        {
            type = CFA_val_offset;
            args.offset = offset;
        }

        void cfa_register(unsigned int reg)
        {
            type = CFA_register;
            args.reg = reg;
        }

        void cfa_expression(FORM<ULEB128> expression)
        {
            type = CFA_expression;
            args.expression = expression;
        }

        void cfa_val_expression(FORM<ULEB128> expression)
        {
            type = CFA_val_expression;
            args.expression = expression;
        }

        void cfa_val(uintptr_t val)
        {
            type = CFA_val;
            args.val = val;
        }

#if defined(__aarch64__)
        uintptr_t aarch64_ra_sign_state() const
        {
            return args.val;
        }

        void cfa_aarch64_negate_ra_state()
        {
            args.val ^= 0x01;
        }

#endif // defined(__aarch64__)

        /// Get register value of next frame based on current frame
        /// @param pointer to the result
        /// @param registers of current frame
        /// @param cfa CFA of the current frame
        /// @return if succeeds, returns UNW_ESUCCESS, otherwise
        ///         returns an error code.
        int get(typename Registers::Word *result, const Registers &regs, typename Registers::Word cfa) const
        {
            switch (type) {
                case CFA_offset:
                    *result = *(typename Registers::Word *)(cfa + args.offset);
                    break;
                case CFA_val_offset:
                    *result = cfa + args.offset;
                    break;
                case CFA_expression:
                case CFA_val_expression: {
                    Buffer buf = args.expression;
                    Expression expression(buf.data, buf.size);
                    uintptr_t val;
                    int ret = expression(&val, regs);
                    if (ret != UNW_ESUCCESS)
                        return ret;

                    if (type == CFA_expression)
                        val = *(uintptr_t *)val;
                    *result = val;
                    break;
                }
                case CFA_register:
                    if (!regs.get_reg(args.reg, result))
                        return UNW_EBADREG;
                    break;
                case CFA_val:
                    *result = args.val;
                    break;
                default:
                    return UNW_EINVAL;
            }

            return UNW_ESUCCESS;
        }

        /// Get register value of next frame based on current frame
        /// @param pointer to the result
        /// @param registers of current frame
        /// @param cfa CFA of the current frame
        /// @return if succeeds, returns UNW_ESUCCESS, otherwise
        ///         returns an error code.
        int get(typename Registers::Float *result, const Registers &regs, typename Registers::Word cfa) const
        {
            switch (type) {
                case CFA_offset:
                    *result = *(typename Registers::Float *)(cfa + args.offset);
                    break;
                case CFA_expression: {
                    Buffer buf = args.expression;
                    Expression expression(buf.data, buf.size);
                    uintptr_t val;
                    int ret = expression(&val, regs);
                    if (ret != UNW_ESUCCESS)
                        return ret;

                    *result = *(typename Registers::Float *)val;
                    break;
                }
                case CFA_register:
                    if (!regs.get_reg(args.reg, result))
                        return UNW_EBADREG;

                    break;
                case CFA_val_offset:
                case CFA_val_expression:
                case CFA_val:
                default:
                    return UNW_EINVAL;
            }

            return UNW_ESUCCESS;
        }

        int get(typename Registers::Vector *result, const Registers &regs, typename Registers::Word cfa) const
        {
            switch (type) {
                case CFA_offset:
                    *result = *(typename Registers::Vector *)(cfa + args.offset);
                    break;
                case CFA_expression: {
                    Buffer buf = args.expression;
                    Expression expression(buf.data, buf.size);
                    uintptr_t val;
                    int ret = expression(&val, regs);
                    if (ret != UNW_ESUCCESS)
                        return ret;

                    *result = *(typename Registers::Vector *)val;
                    break;
                }
                case CFA_register:
                    if (!regs.get_reg(args.reg, result))
                        return UNW_EBADREG;

                    break;
                case CFA_val_offset:
                case CFA_val_expression:
                case CFA_val:
                default:
                    return UNW_EINVAL;
            }

            return UNW_ESUCCESS;
        }

    private:
        int type;
        union {
            ptrdiff_t offset;  // DW_CFA_offset, DW_CFA_offset_extended, DW_CFA_offset_extended_sf, DW_CFA_val_offset, DW_CFA_val_offset_sf
            unsigned int reg;  // DW_CFA_register
            FORM<ULEB128> expression; // DW_CFA_expressio, DW_CFA_val_expression
            uintptr_t val; // DW_CFA_AARCH64_negate_ra_state, DW_CFA_undefined for ra_register
        } args;
    };

    class XRegisters
    {
    public:
        void reset()
        {
            memset(modified, 0, sizeof(modified));

#if defined(__aarch64__)
            xregs[UNW_ARM64_RA_SIGN_STATE].cfa_val(0);
            set_modified(UNW_ARM64_RA_SIGN_STATE, true);
#endif // defined(__aarch64__)
        }

        const XRegister &operator[](unsigned int i) const
        {
            return xregs[i];
        }

        XRegister &operator[](unsigned int i)
        {
            return xregs[i];
        }

        XRegisters &operator=(const XRegisters &rhs)
        {
            for (unsigned int i = 0; i < (sizeof(rhs.modified)/sizeof(rhs.modified[0])); ++i) {
                uintptr_t mask = rhs.modified[i];

                while (mask) {
                    unsigned int offset = ctz(mask);
                    mask ^= (1 << offset);
                    unsigned int reg = (i << SHIFT) + offset;
                    xregs[reg] = rhs.xregs[reg];
                }
            }

            memcpy(modified, &rhs.modified, sizeof(modified));
            return *this;
        }

        bool get_modified(unsigned int reg) const
        {
            return (modified[reg >> SHIFT] & (uintptr_t(1) << (reg & MASK))) != 0;
        }

        void set_modified(unsigned int reg, bool yes = true)
        {
            if (yes)
                modified[reg >> SHIFT] |= uintptr_t(1) << (reg & MASK);
            else
                modified[reg >> SHIFT] &= ~(uintptr_t(1) << (reg & MASK));
        }

        int get(Registers &regs, typename Registers::Word cfa) const
        {
            Registers modified_regs;

            for (unsigned int i = 0; i < sizeof(modified)/sizeof(modified[0]); ++i) {
                uintptr_t mask = modified[i];

                while (mask) {
                    unsigned int offset = ctz(mask);
                    mask ^= (1 << offset);
                    unsigned int reg = (i << SHIFT) + offset;
                    int ret;
                    if (Registers::is_greg(reg)) {
                        typename Registers::Word val;
                        ret = xregs[reg].get(&val, regs, cfa);
                        if (ret != UNW_ESUCCESS)
                            return ret;
                        modified_regs.set_reg(reg, val);
                    } else if (Registers::is_freg(reg)) {
                        typename Registers::Float val;
                        ret = xregs[reg].get(&val, regs, cfa);
                        if (ret != UNW_ESUCCESS)
                            return ret;
                        modified_regs.set_reg(reg, val);
                    } else { // vector registers
                        typename Registers::Vector val;
                        ret = xregs[reg].get(&val, regs, cfa);
                        if (ret != UNW_ESUCCESS)
                            return ret;
                        modified_regs.set_reg(reg, val);
                    }
                }
            }

            for (unsigned int i = 0; i < sizeof(modified)/sizeof(modified[0]); ++i) {
                uintptr_t mask = modified[i];
                while (mask) {
                    unsigned int offset = ctz(mask);
                    mask ^= 1 << offset;
                    unsigned int reg = (i << SHIFT) + offset;
                    if (Registers::is_greg(reg)) {
                        typename Registers::Word val;
                        modified_regs.get_reg(reg, &val);
                        regs.set_reg(reg, val);
                    } else if (Registers::is_freg(reg)) {
                        typename Registers::Float val;
                        modified_regs.get_reg(reg, &val);
                        regs.set_reg(reg, val);
                    } else {
                        typename Registers::Vector val;
                        modified_regs.get_reg(reg, &val);
                        regs.set_reg(reg, val);
                    }
                }
            }

            return UNW_ESUCCESS;
        }

    private:
        enum {
#if __SIZEOF_POINTER__ == 4
            SHIFT = 5,
#elif __SIZEOF_POINTER__ == 8
            SHIFT = 6,
#else
#error Unknown architecture
#endif
            MASK = (1 << SHIFT) - 1,
            LENGTH = (HIGHEST_DWARF_REGISTER + MASK) >> SHIFT,
        };

        uintptr_t modified[LENGTH];
        XRegister xregs[HIGHEST_DWARF_REGISTER];
    };

    int execute(const UnwindInfo &unwind_info)
    {
        XRegisters initial_state;

        uintptr_t location = fde.location;

        // execute initial instructions in CIE
        int ret = execute(unwind_info, cie.instructions.data, cie.instructions.size, location, initial_state);
        if (ret != UNW_ESUCCESS)
            return ret;

        // save initial state
        initial_state = xregs;

        // execute instructions in FDE
        ret = execute(unwind_info, fde.instructions.data, fde.instructions.size, location, initial_state);
        if (ret != UNW_ESUCCESS)
            return ret;

        return UNW_ESUCCESS;
    }

    class State
    {
    public:
        XCFA cfa;
        XRegisters regs;
    };

    /// Execute CIE/FDE dwarf instructions
    /// @param instructions pointer to dwarf instructions
    /// @param size length of dwarf instructions in bytes
    /// @param location initial location of the FDE
    /// @param initial_state initial state after execute dwarf instructions in CIE
    /// @return return UNW_ESUCCESS if the function is succeeds;
    ///         otherwise return and error code less than 0
    int execute(const UnwindInfo &unwind_info,
                const void *instructions,
                size_t size,
                uintptr_t location,
                XRegisters &initial_state)
    {
        uintptr_t ra = unwind_info.ra + unwind_info.signal_frame;

        Stack<State> stack;
        Parser parser(instructions, size, unwind_info.dbase, unwind_info.tbase, fde.location);

        for ( ; ; ) {
            uint8_t op;
            if (!parser.get<uint8_t>(&op))
                return UNW_ESUCCESS; // done

            switch (op) {
                case DW_CFA_nop:
                    break;
                case DW_CFA_set_loc: {
                    if (!parser.get<uintptr_t>(&location, cie.fde_encoding))
                        return UNW_EINVAL;
                    if (location >= ra)
                        return UNW_ESUCCESS;
                    break;
                }
                case DW_CFA_advance_loc1: {
                    uint8_t offset;
                    if (!parser.get<uint8_t>(&offset))
                        return UNW_EINVAL;
                    location += offset * cie.code_align;
                    if (location >= ra)
                        return UNW_ESUCCESS;
                    break;
                }
                case DW_CFA_advance_loc2: {
                    uint16_t offset;
                    if (!parser.get<uint16_t>(&offset))
                        return UNW_EINVAL;
                    location += offset * cie.code_align;
                    if (location >= ra)
                        return UNW_ESUCCESS;
                    break;
                }
                case DW_CFA_advance_loc4: {
                    uint32_t offset;
                    if (!parser.get<uint32_t>(&offset))
                        return UNW_EINVAL;
                    location += offset * cie.code_align;
                    if (location >= ra)
                        return UNW_ESUCCESS;
                    break;
                }
                case DW_CFA_offset_extended: {
                    uint32_t reg;
                    if (!parser.get<ULEB128>(&reg))
                        return UNW_EINVAL;
                    if (reg >= HIGHEST_DWARF_REGISTER)
                        return UNW_EBADREG;
                    ptrdiff_t offset;
                    if (!parser.get<ULEB128>(&offset))
                        return UNW_EINVAL;
                    xregs[reg].cfa_offset(offset * cie.data_align);
                    xregs.set_modified(reg);
                    break;
                }
                case DW_CFA_restore_extended: {
                    uint32_t reg;
                    if (!parser.get<ULEB128>(&reg))
                        return UNW_EINVAL;
                    if (reg >= HIGHEST_DWARF_REGISTER)
                        return UNW_EBADREG;
                    if (initial_state.get_modified(reg))
                        xregs[reg] = initial_state[reg];
                    else
                        xregs.set_modified(reg);
                    break;
                }
                case DW_CFA_undefined: {
                    uint32_t reg;
                    if (!parser.get<ULEB128>(&reg))
                        return UNW_EINVAL;
                    if (reg >= HIGHEST_DWARF_REGISTER)
                        return UNW_EBADREG;
                    if (reg != cie.ra_register) {
                        // for register other than ip, undefined means: it's not modified
                        xregs.set_modified(reg, false);
                    } else {
                        // for ip register, undefined means: set to zero
                        xregs[reg].cfa_val(0);
                        xregs.set_modified(reg, true);
                    }

                    break;
                }
                case DW_CFA_same_value: {
                    uint32_t reg;
                    if (!parser.get<ULEB128>(&reg))
                        return UNW_EINVAL;
                    if (reg >= HIGHEST_DWARF_REGISTER)
                        return UNW_EBADREG;
                    xregs.set_modified(reg, false); // same value always means not modified
                    break;
                }
                case DW_CFA_register: {
                    uint32_t reg;
                    if (!parser.get<ULEB128>(&reg))
                        return UNW_EINVAL;
                    if (reg >= HIGHEST_DWARF_REGISTER)
                        return UNW_EBADREG;
                    uint32_t mirror;
                    if (!parser.get<ULEB128>(&mirror))
                        return UNW_EINVAL;
                    if (mirror >= HIGHEST_DWARF_REGISTER)
                        return UNW_EBADREG;
                    xregs[reg].cfa_register(mirror);
                    xregs.set_modified(reg);
                    break;
                }
                case DW_CFA_remember_state: {
                    typename Stack<State>::Element *p = stack.allocate();
                    if (!p)
                        p = (typename Stack<State>::Element *)__builtin_alloca(sizeof(*p));
                    p->cfa = xcfa;
                    p->regs = xregs;
                    stack.push(p);
                    break;
                }
                case DW_CFA_restore_state: {
                    typename Stack<State>::Element *p = stack.pop();
                    if (!p)
                        return UNW_EINVAL;
                    xcfa = p->cfa;
                    xregs = p->regs;
                    stack.release(p);
                    break;
                }
                case DW_CFA_def_cfa: {
                    uint32_t reg;
                    if (!parser.get<ULEB128>(&reg))
                        return UNW_EINVAL;
                    if (reg >= HIGHEST_DWARF_REGISTER)
                        return UNW_EBADREG;
                    ptrdiff_t offset;
                    if (!parser.get<ULEB128>(&offset))
                        return UNW_EINVAL;
                    xcfa.cfa(reg, offset);
                    break;
                }
                case DW_CFA_def_cfa_register: {
                    uint32_t reg;
                    if (!parser.get<ULEB128>(&reg))
                        return UNW_EINVAL;
                    if (reg >= HIGHEST_DWARF_REGISTER)
                        return UNW_EBADREG;
                    if (!xcfa.cfa_register(reg))
                        return UNW_EINVAL;
                    break;
                }
                case DW_CFA_def_cfa_offset: {
                    ptrdiff_t offset;
                    if (!parser.get<ULEB128>(&offset))
                        return UNW_EINVAL;
                    if (!xcfa.cfa_offset(offset))
                        return UNW_EINVAL;
                    break;
                }
                case DW_CFA_def_cfa_expression: {
                    FORM<ULEB128> expression;
                    if (!parser.get<FORM<ULEB128>>(&expression))
                        return UNW_EINVAL;
                    xcfa.cfa_expression(expression);
                    break;
                }
                case DW_CFA_expression: {
                    uint32_t reg;
                    if (!parser.get<ULEB128>(&reg))
                        return UNW_EINVAL;
                    if (reg >= HIGHEST_DWARF_REGISTER)
                        return UNW_EBADREG;
                    FORM<ULEB128> expression;
                    if (!parser.get<FORM<ULEB128>>(&expression))
                        return UNW_EINVAL;
                    xregs[reg].cfa_expression(expression);
                    xregs.set_modified(reg);
                    break;
                }
                case DW_CFA_offset_extended_sf: {
                    uint32_t reg;
                    if (!parser.get<ULEB128>(&reg))
                        return UNW_EINVAL;
                    if (reg >= HIGHEST_DWARF_REGISTER)
                        return UNW_EBADREG;
                    ptrdiff_t offset;
                    if (!parser.get<SLEB128>(&offset))
                        return UNW_EINVAL;
                    xregs[reg].cfa_offset(offset * cie.data_align);
                    xregs.set_modified(reg);
                    break;
                }
                case DW_CFA_def_cfa_sf: {
                    uint32_t reg;
                    if (!parser.get<ULEB128>(&reg))
                        return UNW_EINVAL;
                    if (reg >= HIGHEST_DWARF_REGISTER)
                        return UNW_EBADREG;
                    ptrdiff_t offset;
                    if (!parser.get<SLEB128>(&offset))
                        return UNW_EINVAL;
                    xcfa.cfa(reg, offset * cie.data_align);
                    break;
                }
                case DW_CFA_def_cfa_offset_sf: {
                    ptrdiff_t offset;
                    if (!parser.get<SLEB128>(&offset))
                        return UNW_EINVAL;
                    if (!xcfa.cfa_offset(offset * cie.data_align))
                        return UNW_EINVAL;
                    break;
                }
                case DW_CFA_val_offset: {
                    uint32_t reg;
                    if (!parser.get<ULEB128>(&reg))
                        return UNW_EINVAL;
                    if (reg >= HIGHEST_DWARF_REGISTER)
                        return UNW_EBADREG;
                    ptrdiff_t offset;
                    if (!parser.get<ULEB128>(&offset))
                        return UNW_EINVAL;
                    xregs[reg].cfa_val_offset(offset * cie.data_align);
                    xregs.set_modified(reg);
                    break;
                }
                case DW_CFA_val_offset_sf:
                    uint32_t reg;
                    if (!parser.get<ULEB128>(&reg))
                        return UNW_EINVAL;
                    if (reg >= HIGHEST_DWARF_REGISTER)
                        return UNW_EBADREG;
                    int32_t offset;
                    if (!parser.get<SLEB128>(&offset))
                        return UNW_EINVAL;
                    xregs[reg].cfa_val_offset(offset * cie.data_align);
                    xregs.set_modified(reg);
                    break;
                case DW_CFA_val_expression: {
                    uint32_t reg;
                    if (!parser.get<ULEB128>(&reg))
                        return UNW_EINVAL;
                    if (reg >= HIGHEST_DWARF_REGISTER)
                        return UNW_EBADREG;
                    FORM<ULEB128> expression;
                    if (!parser.get<FORM<ULEB128>>(&expression))
                        return UNW_EINVAL;
                    xregs[reg].cfa_val_expression(expression);
                    xregs.set_modified(reg);
                    break;
                }
                case DW_CFA_GNU_args_size:
                    if (!parser.get<ULEB128>(&args_size))
                        return UNW_EINVAL;
                    break;
                case DW_CFA_GNU_negative_offset_extended: {
                    uint32_t reg;
                    if (!parser.get<ULEB128>(&reg))
                        return UNW_EINVAL;
                    if (reg >= HIGHEST_DWARF_REGISTER)
                        return UNW_EBADREG;
                    ptrdiff_t offset;
                    if (!parser.get<ULEB128>(&offset))
                        return UNW_EINVAL;
                    xregs[reg].cfa_offset(-offset * cie.data_align);
                    xregs.set_modified(reg);
                    break;
                }
#if defined(__aarch64__)
                case DW_CFA_AARCH64_negate_ra_state:
                    xregs[UNW_ARM64_RA_SIGN_STATE].cfa_aarch64_negate_ra_state();
                    break;
#endif // defined(__aarch64__)
                default:
                    switch (op & 0xC0) {
                        case DW_CFA_offset: {
                            uint32_t reg = op & 0x3f;
                            if (reg >= HIGHEST_DWARF_REGISTER)
                                return UNW_EBADREG;
                            ptrdiff_t offset;
                            if (!parser.get<ULEB128>(&offset))
                                return UNW_EINVAL;
                            xregs[reg].cfa_offset(offset * cie.data_align);
                            xregs.set_modified(reg);
                            break;
                        }
                        case DW_CFA_advance_loc: {
                            uint32_t offset = op & 0x3f;
                            location += offset * cie.code_align;
                            if (location >= ra)
                                return UNW_ESUCCESS;

                            break;
                        }
                        case DW_CFA_restore: {
                            uint32_t reg = op & 0x3f;
                            if (reg >= HIGHEST_DWARF_REGISTER)
                                return UNW_EBADREG;
                            if (initial_state.get_modified(reg))
                                xregs[reg] = initial_state[reg];
                            else
                                xregs.set_modified(reg, false);
                            break;
                        }
                    }
            }
        }
    }

    int parse(const UnwindInfo &unwind_info, const struct eh_frame_hdr *eh_frame_hdr, size_t size)
    {
        if ((eh_frame_hdr->version != 1) || (size < sizeof(struct eh_frame_hdr)))
            return UNW_EBADVERSION; // Unsupported .eh_frame_hdr version

        size_t log2_size;
        switch (eh_frame_hdr->table_enc & 0x0f) {
            case DW_EH_PE_sdata2:
            case DW_EH_PE_udata2:
                log2_size = 2; // 2 uint16_t
                break;
            case DW_EH_PE_sdata4:
            case DW_EH_PE_udata4:
                log2_size = 3; // 2 uint32_t
                break;
            case DW_EH_PE_sdata8:
            case DW_EH_PE_udata8:
                log2_size = 4; // 2 uint64_t
                break;
            case DW_EH_PE_ptr:
                if (sizeof(uintptr_t) == 4) {
                    log2_size = 3;
                    break;
                } else if (sizeof(uintptr_t) == 8) {
                    log2_size = 4;
                    break;
                }
            case DW_EH_PE_sleb128:
            case DW_EH_PE_uleb128: // Can't binary search on variable length encoded data.
            case DW_EH_PE_omit:
            default: // Unknown DWARF encoding for search table.
                return UNW_EINVAL;
        }

        Parser parser(eh_frame_hdr + 1,
                      size - sizeof(struct eh_frame_hdr),
                      (uintptr_t)eh_frame_hdr);

        uintptr_t eh_frame;
        if (!parser.get(&eh_frame, eh_frame_hdr->eh_frame_ptr_enc))
            return UNW_EINVAL;

        size_t range;
        if (!parser.get(&range, eh_frame_hdr->fde_count_enc))
            return UNW_EINVAL;

        if (range == 0)
            return UNW_ENOINFO;

        size_t base = parser.tell();

        // For signal frame, the return address is IP to the last executed
        // instruction, in this case, all FDE instructions satisfied the
        // condition location <= ra should be executed.
        //
        // For non-signal frame, the return address is IP to the next
        // instruction after the call instruction, in this case, all FDE
        // instructions satisfied the condition location < ra shoud be
        // executed.
        // For non-signal frame, if a function calls a noreturn function
        // in the end of function, the IP of return address will be located
        // in another FDE, in this case, the ra - 1 shoud be used to find
        // the correct FDE, and for non-signal frame, the ra - 1 is still in
        // the same FDE, since the ra - 1 is always point to a byte in call
        // instruction.
        // The unwind logic will be:
        // For signal frame:
        //     use ra to find FDE
        //     execute FDE instructions for location < ra + 1
        // For non-signal frame:
        //     use ra - 1 to find FDE
        //     execute FDE instrctions for location < ra
        uintptr_t ra = unwind_info.ra - (unwind_info.signal_frame ^ 0x01);
        for ( ; ; ) {
            uintptr_t location;
            size_t offset = base + ((range/2) << log2_size);
            if (!parser.seek(offset, Origin::BEGIN) ||
                !parser.get(&location, eh_frame_hdr->table_enc))
                return UNW_EINVAL;

            if (ra < location) {
                if (!(range /= 2))
                    return UNW_ENOINFO;
            } else {
                if (range < 2)
                    break;

                base = offset;
                range -= range/2;
            }
        }

        const void *fde_address;
        if (!parser.get(&fde_address, eh_frame_hdr->table_enc))
            return UNW_EINVAL;

        int ret;
        ret = fde.parse(unwind_info, cie, fde_address);
        if (ret != UNW_ESUCCESS)
            return ret;

        if ((ra < fde.location) || (ra >= (fde.location + fde.address_range)))
            return UNW_ENOINFO;

        return execute(unwind_info);
    }

    int parse(const UnwindInfo &unwind_info, struct eh_frame *eh_frame, size_t size)
    {
        const unsigned char *p = (const unsigned char *)eh_frame;

        for ( ; ; ) {
            int ret;
            ret = cie.parse(unwind_info, p, size);
            if (ret != UNW_ESUCCESS)
                return ret;

            p += cie.length;
            size -= cie.length;

            for ( ; ; ) {
                ret = fde.parse(unwind_info, cie, p, size);
                if (ret != UNW_ESUCCESS) {
                    if (ret == UNW_ENOINFO)
                        break; // possible CIE encounted
                    return ret;
                }

                if ((unwind_info.ra >= fde.location) && (unwind_info.ra < (fde.location + fde.address_range)))
                    return execute(unwind_info);

                p += fde.length;
                size -= fde.length;
            }
        }
    }

    CIE cie;
    FDE fde;
    unsigned int args_size;
    XCFA xcfa;
    XRegisters xregs;
};

template<typename UnwindInfo>
class UnwindCursor
{
public:
    UnwindCursor(Registers &regs): regs(regs)
    {
    }

    void *operator new(size_t size, void *p)
    {
        return p;
    }

    int init(int flags = 0)
    {
        uintptr_t ra = regs.get_ip();
        if (!ra)
            return UNW_ENOINFO;

        // TODO: if (flags & UNW_INIT_SIGNAL_FRAME)
            
        UnwindInfo unwind_info(ra, false);
        return cfi.parse(unwind_info);
    }

    int get_reg(unw_regnum_t reg, unw_word_t *value)
    {
        return regs.get_reg(reg, value) ? UNW_ESUCCESS : UNW_EBADREG;
    }

    int set_reg(unw_regnum_t reg, unw_word_t value)
    {
        if (!regs.set_reg(reg, value))
            return UNW_EBADREG;

        //if (reg == UNW_REG_IP)
        //    regs.set_sp(regs.get_sp() + info.gp);

        return UNW_ESUCCESS;
    }

    int get_fpreg(unw_regnum_t reg, unw_fpreg_t *value)
    {
        return regs.get_reg(reg, value);
    }

    int set_fpreg(unw_regnum_t reg, unw_fpreg_t value)
    {
        return regs.set_reg(reg, value);
    }

    const char *regname(unw_regnum_t reg)
    {
        return regs.get_name(reg);
    }

    int step()
    {
        int ret = cfi.get(regs);
        if (ret != UNW_ESUCCESS)
            return ret;

        uintptr_t ra = regs.get_ip();
        if (!ra)
            return UNW_STEP_END;

        UnwindInfo unwind_info(ra, cfi.is_signal_frame());
        ret = cfi.parse(unwind_info);
        if (ret != UNW_ESUCCESS)
            return ret != UNW_ENOINFO ? ret : UNW_STEP_END;

        return UNW_STEP_SUCCESS;
    }

    int get_proc_info(unw_proc_info_t *info)
    {
        return cfi.get_proc_info(info);
    }

    int is_signal_frame()
    {
        return cfi.is_signal_frame();
    }

    void resume()
    {
        regs.restore();
    }

private:
    CFI cfi;
    Registers &regs;
};
} // namespace dwarf

#endif // DWARF_PARSER_HPP

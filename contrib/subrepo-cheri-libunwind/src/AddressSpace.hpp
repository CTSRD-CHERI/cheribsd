//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//
// Abstracts accessing local vs remote address spaces.
//
//===----------------------------------------------------------------------===//

#ifndef __ADDRESSSPACE_HPP__
#define __ADDRESSSPACE_HPP__

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libunwind.h"
#include "config.h"
#include "dwarf2.h"
#include "EHHeaderParser.hpp"
#include "Registers.hpp"

// We can no longer include C++ headers so duplicate std::min() here
template<typename T> T uw_min(T a, T b) { return a < b ? a : b; }

#ifndef _LIBUNWIND_USE_DLADDR
  #if !defined(_LIBUNWIND_IS_BAREMETAL) && !defined(_WIN32)
    #define _LIBUNWIND_USE_DLADDR 1
  #else
    #define _LIBUNWIND_USE_DLADDR 0
  #endif
#endif

#if _LIBUNWIND_USE_DLADDR
#include <dlfcn.h>
#if defined(__ELF__) && defined(_LIBUNWIND_LINK_DL_LIB)
#pragma comment(lib, "dl")
#endif
#endif

#if defined(_LIBUNWIND_ARM_EHABI)
struct EHABIIndexEntry {
  uint32_t functionOffset;
  uint32_t data;
};
#endif

#ifdef __APPLE__

  struct dyld_unwind_sections
  {
    const struct mach_header*   mh;
    const void*                 dwarf_section;
    uintptr_t                   dwarf_section_length;
    const void*                 compact_unwind_section;
    uintptr_t                   compact_unwind_section_length;
  };

  // In 10.7.0 or later, libSystem.dylib implements this function.
  extern "C" bool _dyld_find_unwind_sections(void *, dyld_unwind_sections *);

#elif defined(_LIBUNWIND_SUPPORT_DWARF_UNWIND) && defined(_LIBUNWIND_IS_BAREMETAL)

// When statically linked on bare-metal, the symbols for the EH table are looked
// up without going through the dynamic loader.

// The following linker script may be used to produce the necessary sections and symbols.
// Unless the --eh-frame-hdr linker option is provided, the section is not generated
// and does not take space in the output file.
//
//   .eh_frame :
//   {
//       __eh_frame_start = .;
//       KEEP(*(.eh_frame))
//       __eh_frame_end = .;
//   }
//
//   .eh_frame_hdr :
//   {
//       KEEP(*(.eh_frame_hdr))
//   }
//
//   __eh_frame_hdr_start = SIZEOF(.eh_frame_hdr) > 0 ? ADDR(.eh_frame_hdr) : 0;
//   __eh_frame_hdr_end = SIZEOF(.eh_frame_hdr) > 0 ? . : 0;

extern char __eh_frame_start;
extern char __eh_frame_end;

#if defined(_LIBUNWIND_SUPPORT_DWARF_INDEX)
extern char __eh_frame_hdr_start;
extern char __eh_frame_hdr_end;
#endif

#elif defined(_LIBUNWIND_ARM_EHABI) && defined(_LIBUNWIND_IS_BAREMETAL)

// When statically linked on bare-metal, the symbols for the EH table are looked
// up without going through the dynamic loader.
extern char __exidx_start;
extern char __exidx_end;

#elif defined(_LIBUNWIND_SUPPORT_DWARF_UNWIND) && defined(_WIN32)

#include <windows.h>
#include <psapi.h>

#elif defined(_LIBUNWIND_USE_DL_ITERATE_PHDR) ||                               \
      defined(_LIBUNWIND_USE_DL_UNWIND_FIND_EXIDX)

#include <link.h>

#endif

namespace libunwind {

/// Used by findUnwindSections() to return info about needed sections.
struct UnwindInfoSections {
#if defined(_LIBUNWIND_SUPPORT_DWARF_UNWIND) ||                                \
    defined(_LIBUNWIND_SUPPORT_COMPACT_UNWIND) ||                              \
    defined(_LIBUNWIND_USE_DL_ITERATE_PHDR)
  // No dso_base for SEH.
  uintptr_t       dso_base;
#endif
#if defined(_LIBUNWIND_USE_DL_ITERATE_PHDR)
  size_t          text_segment_length;
#endif
#if defined(_LIBUNWIND_SUPPORT_DWARF_UNWIND)
private:
  uintptr_t       __dwarf_section;
public:
  void set_dwarf_section(uintptr_t value) {
      __dwarf_section = assert_pointer_in_bounds(value);
  }
  uintptr_t dwarf_section() const { return __dwarf_section; }
  size_t          dwarf_section_length;
#endif
#if defined(_LIBUNWIND_SUPPORT_DWARF_INDEX)
private:
  uintptr_t       __dwarf_index_section;
public:
  void set_dwarf_index_section(uintptr_t value) {
      __dwarf_index_section = assert_pointer_in_bounds(value);
  }
  uintptr_t dwarf_index_section() const { return __dwarf_index_section; }
  size_t          dwarf_index_section_length;
#endif
#if defined(_LIBUNWIND_SUPPORT_COMPACT_UNWIND)
  uintptr_t       compact_unwind_section;
  size_t          compact_unwind_section_length;
#endif
#if defined(_LIBUNWIND_ARM_EHABI)
  uintptr_t       arm_section;
  size_t          arm_section_length;
#endif
};

/// LocalAddressSpace is used as a template parameter to UnwindCursor when
/// unwinding a thread in the same process.  The wrappers compile away,
/// making local unwinds fast.
class _LIBUNWIND_HIDDEN LocalAddressSpace {
public:
  typedef uintptr_t pint_t;
  typedef intptr_t  sint_t;
#ifndef __CHERI__
  typedef libunwind::fake_capability_t capability_t;
#else
  typedef ::uintcap_t capability_t;
#endif
#ifdef __CHERI_PURE_CAPABILITY__
  typedef uint64_t addr_t;
#elif defined(__LP64__)
  typedef uint64_t addr_t;
#else
  typedef uint32_t addr_t;
#endif
  // A thin wrapper around uintptr_t.
  // This is used to ensure that return addresses are used correctly for CHERI
  // where they might be sealed entry ("sentry") capabilities that cannot be
  // modified.
  class LocalProgramCounter {
    void *value;
#ifdef __CHERI_PURE_CAPABILITY__
    // the actual pc might be a sentry but libunwind needs to modify it
    // sometimes
    uint64_t addend = 0;
    LocalProgramCounter(void *v, uint64_t a) : value(v), addend(a) {}
#endif

  public:
    explicit LocalProgramCounter() : value(nullptr) {}
    explicit LocalProgramCounter(uintptr_t v) : value((void *)v) {
#ifdef __CHERI_PURE_CAPABILITY__
      if (!isNull() && !isValid())
        _LIBUNWIND_ABORT_FMT("Untagged non-null value " _LIBUNWIND_FMT_PTR
                             " used as program counter",
                             value);
#endif
    }
#ifdef __CHERI_PURE_CAPABILITY__
    // Ensure that we don't accidentally create untagged values from integers
    LocalProgramCounter(uint64_t) = delete;
    LocalProgramCounter(int64_t) = delete;
#endif
    bool isImmutable() const {
#ifdef __CHERI_PURE_CAPABILITY__
      return __builtin_cheri_sealed_get(value);
#else
      return false;
#endif
    }
    LocalProgramCounter assertInBounds(addr_t addr) const {
#ifdef __CHERI_PURE_CAPABILITY__
      if (!__builtin_cheri_tag_get(value)) {
        _LIBUNWIND_ABORT_FMT("Untagged value " _LIBUNWIND_FMT_PTR
                             " used as program counter",
                             value);
      }
      // We might not be able to modify value -> inspect values instead of
      // adding and the checking if it is in bounds
      addr_t base = __builtin_cheri_base_get(value);
      size_t length = __builtin_cheri_length_get(value);
      if (addr < base || addr >= base + length) {
        _LIBUNWIND_ABORT_FMT("Address 0x%jx is outside program counter "
                             "value " _LIBUNWIND_FMT_PTR,
                             (uintmax_t)addr, value);
      }
      if (isImmutable()) {
        // For sentries we have to modify the addend instead of creating a new
        // capability from value.
        return LocalProgramCounter(value,
                                   addr - __builtin_cheri_address_get(value));
      } else {
        return LocalProgramCounter(__builtin_cheri_address_set(value, addr), 0);
      }
#else
      return LocalProgramCounter(addr);
#endif
    }
    bool isNull() const { return value == nullptr; }
    bool isValid() const {
#ifdef __CHERI_PURE_CAPABILITY__
      return __builtin_cheri_tag_get(value);
#else
      return !isNull();
#endif
    }
    // explicit operator void*() { return value; }
    // explicit operator char*() { return (char*)value; }
    // explicit operator pint_t() { return (pint_t)value; }
    // Note: this ignores the added so should only be used for printf
    struct ImmutablePointer {};
    ImmutablePointer *get() const { return (ImmutablePointer *)value; }
    addr_t address() const {
#ifdef __CHERI_PURE_CAPABILITY__
      return __builtin_cheri_address_get(value) + addend;
#else
      return (addr_t)(uintptr_t)value;
#endif
    }
    LocalProgramCounter &operator--() {
#ifdef __CHERI_PURE_CAPABILITY__
      if (isImmutable()) {
        addend--;
        return *this;
      }
#else
      value = (void *)((uintptr_t)value - 1);
#endif
      return *this;
    }
    LocalProgramCounter &operator&=(addr_t a) {
#ifdef __CHERI_PURE_CAPABILITY__
      if (isImmutable()) {
        addr_t new_addr = address() & a;
        addend = new_addr - address();
        return *this;
      }
#else
      value = (void *)((uintptr_t)value & a);
#endif
      return *this;
    }
  };
  typedef LocalProgramCounter pc_t;

  template<typename T>
  inline T get(pint_t addr) {
    T val;
#ifdef __CHERI_PURE_CAPABILITY__
    assert(__builtin_cheri_tag_get((void*)addr) && "Value should be tagged!");
#endif
    memcpy(&val, (T*)(void *)addr, sizeof(val));
    return val;
  }
  uint8_t         get8(pint_t addr) {
    return get<uint8_t>(addr);
  }
  uint16_t         get16(pint_t addr) {
    return get<uint16_t>(addr);
  }
  uint32_t         get32(pint_t addr) {
    return get<uint32_t>(addr);
  }
  uint64_t         get64(pint_t addr) {
    return get<uint64_t>(addr);
  }
  double           getDouble(pint_t addr) {
    return get<double>(addr);
  }
  v128             getVector(pint_t addr) {
    return get<v128>(addr);
  }
  capability_t     getCapability(pint_t addr) { return get<capability_t>(addr); }
  __attribute__((always_inline))
  uintptr_t       getP(pint_t addr);
  uint64_t        getRegister(pint_t addr);
  static uint64_t getULEB128(pint_t &addr, pint_t end);
  static int64_t  getSLEB128(pint_t &addr, pint_t end);

  pint_t getEncodedP(pint_t &addr, pint_t end, uint8_t encoding,
                     pint_t datarelBase = 0);
  bool findFunctionName(pc_t ip, char *buf, size_t bufLen, unw_word_t *offset);
  bool findUnwindSections(pc_t targetAddr, UnwindInfoSections &info);
  bool findOtherFDE(addr_t targetAddr, pint_t &fde);

  static LocalAddressSpace sThisAddressSpace;

  static pint_t to_pint_t(capability_t cap) {
#ifdef __CHERI_PURE_CAPABILITY__
    return (uintcap_t)cap;
#elif defined(__CHERI__)
    return (__cheri_addr pint_t)cap;
#else
    pint_t result;
    memcpy(&result, &cap, uw_min(sizeof(result), sizeof(cap)));
    return result;
#endif
  }
  static capability_t to_capability_t(pint_t pint) {
#ifdef __CHERI__
    return (uintcap_t)pint;
#else
    capability_t result;
    memcpy(&result, &pint, uw_min(sizeof(result), sizeof(pint)));
    return result;
#endif
  }
};

#ifdef __CHERI_PURE_CAPABILITY__
#define _pint_to_addr(val) (__builtin_cheri_address_get((void*)val))
#define PC_T_PINT_T_COMPARATORS(op)                                            \
  inline bool operator op(LocalAddressSpace::pint_t lhs,                       \
                          const LocalAddressSpace::pc_t &rhs) {                \
    return _pint_to_addr(lhs) op rhs.address();                                \
  }                                                                            \
  inline bool operator op(const LocalAddressSpace::pc_t &lhs,                  \
                          LocalAddressSpace::pint_t rhs) {                     \
    return lhs.address() op _pint_to_addr(rhs);                                \
  }
#else
#define PC_T_PINT_T_COMPARATORS(op) /* nothing */
#define _pint_to_addr(val) ((LocalAddressSpace::addr_t)val)
#endif

// Comparison operators for pc_t:
// Note: we ignore the tag in these comparisons
#define PC_T_COMPARATOR(op)                                                    \
  PC_T_PINT_T_COMPARATORS(op)                                                  \
  inline bool operator op(LocalAddressSpace::addr_t lhs,                       \
                          const LocalAddressSpace::pc_t &rhs) {                \
    return lhs op rhs.address();                                               \
  }                                                                            \
  inline bool operator op(const LocalAddressSpace::pc_t &lhs,                  \
                          LocalAddressSpace::addr_t rhs) {                     \
    return lhs.address() op rhs;                                               \
  }                                                                            \
  inline bool operator op(const LocalAddressSpace::pc_t &lhs,                  \
                          const LocalAddressSpace::pc_t &rhs) {                \
    return lhs.address() op rhs.address();                                     \
  }

PC_T_COMPARATOR(<)
PC_T_COMPARATOR(<=)
PC_T_COMPARATOR(>=)
PC_T_COMPARATOR(>)
PC_T_COMPARATOR(==)
PC_T_COMPARATOR(!=)

inline uintptr_t LocalAddressSpace::getP(pint_t addr) {
  return get<uintptr_t>(addr);
}

inline uint64_t LocalAddressSpace::getRegister(pint_t addr) {
#if __SIZEOF_POINTER__ == 8 || defined(__mips64)
  return get64(addr);
#else
  return get32(addr);
#endif
}

/// Read a ULEB128 into a 64-bit word.
inline uint64_t LocalAddressSpace::getULEB128(pint_t &addr, pint_t end) {
  const uint8_t *p = (uint8_t *)addr;
  const uint8_t *pend = (uint8_t *)end;
  uint64_t result = 0;
  int bit = 0;
  do {
    uint64_t b;

    if (p == pend)
      _LIBUNWIND_ABORT("truncated uleb128 expression");

    b = *p & 0x7f;

    if (bit >= 64 || b << bit >> bit != b) {
      _LIBUNWIND_ABORT("malformed uleb128 expression");
    } else {
      result |= b << bit;
      bit += 7;
    }
  } while (*p++ >= 0x80);
  addr = (pint_t) p;
  return result;
}

/// Read a SLEB128 into a 64-bit word.
inline int64_t LocalAddressSpace::getSLEB128(pint_t &addr, pint_t end) {
  const uint8_t *p = (uint8_t *)addr;
  const uint8_t *pend = (uint8_t *)end;
  int64_t result = 0;
  int bit = 0;
  uint8_t byte;
  do {
    if (p == pend)
      _LIBUNWIND_ABORT("truncated sleb128 expression");
    byte = *p++;
    result |= (uint64_t)(byte & 0x7f) << bit;
    bit += 7;
  } while (byte & 0x80);
  // sign extend negative numbers
  if ((byte & 0x40) != 0 && bit < 64)
    result |= (-1ULL) << bit;
  addr = (pint_t) p;
  return result;
}

template<typename T1, typename T2>
constexpr int check_same_type() {
  static_assert(__is_same(T1, T2), "Should be same type! Update CheriBSD!");
  return 0;
}

#ifdef __CHERI_PURE_CAPABILITY__
__attribute__((weak)) extern "C" Elf_Dyn _DYNAMIC[];
// #pragma weak _DYNAMIC
#endif

inline LocalAddressSpace::pint_t
LocalAddressSpace::getEncodedP(pint_t &addr, pint_t end, uint8_t encoding,
                               pint_t datarelBase) {
  pint_t startAddr = addr;
  const uint8_t *p = (uint8_t *)addr;
  pint_t result;

  // first get value
  switch (encoding & 0x0F) {
  case DW_EH_PE_ptr:
    result = assert_pointer_in_bounds(getP(addr));
    p += sizeof(pint_t);
    addr = (pint_t) p;
    break;
  case DW_EH_PE_uleb128:
    result = (pint_t)getULEB128(addr, end);
    break;
  case DW_EH_PE_udata2:
    result = get16(addr);
    p += 2;
    addr = (pint_t) p;
    break;
  case DW_EH_PE_udata4:
    result = get32(addr);
    p += 4;
    addr = (pint_t) p;
    break;
  case DW_EH_PE_udata8:
    result = (pint_t)get64(addr);
    p += 8;
    addr = (pint_t) p;
    break;
  case DW_EH_PE_sleb128:
    result = (pint_t)getSLEB128(addr, end);
    break;
  case DW_EH_PE_sdata2:
    // Sign extend from signed 16-bit value.
    result = (pint_t)(int16_t)get16(addr);
    p += 2;
    addr = (pint_t) p;
    break;
  case DW_EH_PE_sdata4:
    // Sign extend from signed 32-bit value.
    result = (pint_t)(int32_t)get32(addr);
    p += 4;
    addr = (pint_t) p;
    break;
  case DW_EH_PE_sdata8:
    result = (pint_t)get64(addr);
    p += 8;
    addr = (pint_t) p;
    break;
  default:
    _LIBUNWIND_ABORT("unknown pointer encoding");
  }

  // then add relative offset
  switch (encoding & 0x70) {
  case DW_EH_PE_absptr:
    // do nothing
    break;
  case DW_EH_PE_pcrel:
    // Note: for CHERI we must add the result (untagged offset) to startAddr
    // to get a value with valid tag since uintptr_t addition is not commutative
    result = assert_pointer_in_bounds(startAddr + _pint_to_addr(result));
    break;
  case DW_EH_PE_textrel:
    _LIBUNWIND_ABORT("DW_EH_PE_textrel pointer encoding not supported");
    break;
  case DW_EH_PE_datarel:
    // DW_EH_PE_datarel is only valid in a few places, so the parameter has a
    // default value of 0, and we abort in the event that someone calls this
    // function with a datarelBase of 0 and DW_EH_PE_datarel encoding.
    if (datarelBase == 0)
      _LIBUNWIND_ABORT("DW_EH_PE_datarel is invalid with a datarelBase of 0");
    // Note: for CHERI we must add the result (untagged offset) to startAddr
    // to get a value with valid tag since uintptr_t addition is not commutative
    assert_pointer_in_bounds(datarelBase);
    result = assert_pointer_in_bounds(datarelBase + _pint_to_addr(result));
    break;
  case DW_EH_PE_funcrel:
    _LIBUNWIND_ABORT("DW_EH_PE_funcrel pointer encoding not supported");
    break;
  case DW_EH_PE_aligned:
    _LIBUNWIND_ABORT("DW_EH_PE_aligned pointer encoding not supported");
    break;
  default:
    _LIBUNWIND_ABORT("unknown pointer encoding");
    break;
  }

  if (encoding & DW_EH_PE_indirect) {
    // Always read a pointer sized value for DW_EH_PE_indirect
    // This seems to be the way that GNU tools interpret this but it will almost
    // certainly cause some issues for CHERI since we might want non-capability
    // values to be indirect to avoid RODATA relocations.
    result = getP(assert_pointer_in_bounds(result));
#ifdef __CHERI_PURE_CAPABILITY__
    assert_pointer_in_bounds(result);
#endif
  }

  return result;
}

#if defined(_LIBUNWIND_USE_DL_ITERATE_PHDR)

// The ElfW() macro for pointer-size independent ELF header traversal is not
// provided by <link.h> on some systems (e.g., FreeBSD). On these systems the
// data structures are just called Elf_XXX. Define ElfW() locally.
#if !defined(ElfW)
  #define ElfW(type) Elf_##type
#endif
#if !defined(Elf_Half)
typedef ElfW(Half) Elf_Half;
#endif
#if !defined(Elf_Phdr)
typedef ElfW(Phdr) Elf_Phdr;
#endif
#if !defined(Elf_Addr)
typedef ElfW(Addr) Elf_Addr;
#endif

static uintptr_t calculateImageBase(struct dl_phdr_info *pinfo) {
  uintptr_t image_base = static_cast<uintptr_t>(pinfo->dlpi_addr);
#if defined(__ANDROID__) && __ANDROID_API__ < 18
  if (image_base == 0) {
    // Normally, an image base of 0 indicates a non-PIE executable. On
    // versions of Android prior to API 18, the dynamic linker reported a
    // dlpi_addr of 0 for PIE executables. Compute the true image base
    // using the PT_PHDR segment.
    // See https://github.com/android/ndk/issues/505.
    for (Elf_Half i = 0; i < pinfo->dlpi_phnum; i++) {
      const Elf_Phdr *phdr = &pinfo->dlpi_phdr[i];
      if (phdr->p_type == PT_PHDR) {
        image_base = static_cast<uintptr_t>(pinfo->dlpi_phdr) - phdr->p_vaddr;
        break;
      }
    }
  }
#endif
#ifdef __CHERI_PURE_CAPABILITY__
  // For statically linked pure-capability programs, it is generally not
  // possible to have a dlpi_addr capabibility with address zero but the bounds
  // of the executable mapping because capability compression prevents
  // creation of such a massively out-of-bounds capability.
  // Therefore, the kernel and libc ensure that dlpi_addr is (untagged) zero
  // and dpli_phdr spans the executable mapping.
  if (image_base == 0 && !__builtin_cheri_tag_get((void *)image_base)) {
    image_base = (uintptr_t)pinfo->dlpi_phdr;
  }
#endif
  return image_base;
}

struct _LIBUNWIND_HIDDEN dl_iterate_cb_data {
  LocalAddressSpace *addressSpace;
  UnwindInfoSections *sects;
  LocalAddressSpace::pc_t targetAddr;
};

static LocalAddressSpace::pint_t getPhdrCapability(uintptr_t image_base,
                                                   const Elf_Phdr *phdr) {
#ifdef __CHERI_PURE_CAPABILITY__
  // We have to work around the position dependent linking case where
  // dlpi_addr will contain just the binary range (and can't a be massively
  // out of bounds cap with a zero vaddr due to Cheri128 constaints). In that
  // case phdr->p_vaddr will be within the bounds of image_base so we
  // just set the address to match the vaddr
  if (&_DYNAMIC == NULL) {
    // static linking / position dependent workaround:
    LocalAddressSpace::addr_t base =
        __builtin_cheri_base_get((void *)image_base);
    LocalAddressSpace::addr_t end =
        base + __builtin_cheri_length_get((void *)image_base);
    if (phdr->p_vaddr >= base && phdr->p_vaddr < end) {
      return (uintptr_t)__builtin_cheri_address_set((void *)image_base,
                                                    phdr->p_vaddr);
    }
  }
  // Otherwise just fall back to the default behaviour
  if (!__builtin_cheri_tag_get((void *)(image_base + phdr->p_vaddr)))
    _LIBUNWIND_ABORT("phdr cap became unpresentable?");
#endif
  return image_base + phdr->p_vaddr;
}

#if defined(_LIBUNWIND_USE_FRAME_HEADER_CACHE)
#include "FrameHeaderCache.hpp"

// Typically there is one cache per process, but when libunwind is built as a
// hermetic static library, then each shared object may have its own cache.
static FrameHeaderCache TheFrameHeaderCache;
#endif

static bool checkAddrInSegment(const Elf_Phdr *phdr, uintptr_t image_base,
                               dl_iterate_cb_data *cbdata) {
  if (phdr->p_type == PT_LOAD) {
    uintptr_t begin = getPhdrCapability(image_base, phdr);
    uintptr_t end = begin + phdr->p_memsz;
    if (cbdata->targetAddr >= begin && cbdata->targetAddr < end) {
      cbdata->sects->dso_base = begin;
      cbdata->sects->text_segment_length = phdr->p_memsz;
      return true;
    }
  }
  return false;
}

#define PINFO_NAME(pinfo)                                                      \
  ((pinfo->dlpi_name && pinfo->dlpi_name[0] != '\0') ? pinfo->dlpi_name        \
                                                     : "<self>")

static bool boundEhFrameFromPhdr(struct dl_phdr_info *pinfo,
                                 uintptr_t image_base,
                                 dl_iterate_cb_data *cbdata) {
  CHERI_DBG("Trying to bound PT_LOAD of .eh_frame in %s\n", PINFO_NAME(pinfo));
  uintptr_t target_addr = cbdata->sects->dwarf_section();
  for (Elf_Half i = 0; i < pinfo->dlpi_phnum; i++) {
    const Elf_Phdr *phdr = &pinfo->dlpi_phdr[i];
    if (phdr->p_type == PT_LOAD) {
      uintptr_t begin = getPhdrCapability(image_base, phdr);
      uintptr_t end = begin + phdr->p_memsz;
      if (target_addr >= begin && target_addr < end) {
        // This still overestimates the length of .eh_frame, but it
        // should respect the bounds of the containing PT_LOAD.
        cbdata->sects->dwarf_section_length =
            phdr->p_memsz -
            (size_t)((char *)cbdata->sects->dwarf_section() - (char *)begin);
        return true;
      }
    }
  }
  CHERI_DBG("Could not find PT_LOAD of .eh_frame in %s\n", PINFO_NAME(pinfo));
  return false;
}

static bool checkForUnwindInfoSegment(const Elf_Phdr *phdr, uintptr_t image_base,
                                      dl_iterate_cb_data *cbdata) {
#if defined(_LIBUNWIND_SUPPORT_DWARF_INDEX)
  if (phdr->p_type == PT_GNU_EH_FRAME) {
    EHHeaderParser<LocalAddressSpace>::EHHeaderInfo hdrInfo;
    uintptr_t eh_frame_hdr_start = getPhdrCapability(image_base, phdr);
#ifdef __CHERI_PURE_CAPABILITY__
    if (!__builtin_cheri_tag_get((void *)eh_frame_hdr_start))
        _LIBUNWIND_ABORT("eh_frame_hdr_start cap became unpresentable!");
#endif
    cbdata->sects->set_dwarf_index_section(eh_frame_hdr_start);
    cbdata->sects->dwarf_index_section_length = phdr->p_memsz;
    if (EHHeaderParser<LocalAddressSpace>::decodeEHHdr(
            *cbdata->addressSpace, eh_frame_hdr_start, phdr->p_memsz,
            hdrInfo)) {
      // .eh_frame_hdr records the start of .eh_frame, but not its size.
      // Rely on a zero terminator to find the end of the section.
      cbdata->sects->set_dwarf_section(hdrInfo.eh_frame_ptr);
      cbdata->sects->dwarf_section_length = SIZE_MAX;
      return true;
    }
  }
  return false;
#elif defined(_LIBUNWIND_ARM_EHABI)
  if (phdr->p_type == PT_ARM_EXIDX) {
    uintptr_t exidx_start = image_base + phdr->p_vaddr;
    cbdata->sects->arm_section = exidx_start;
    cbdata->sects->arm_section_length = phdr->p_memsz;
    return true;
  }
  return false;
#else
#error Need one of _LIBUNWIND_SUPPORT_DWARF_INDEX or _LIBUNWIND_ARM_EHABI
#endif
}

static int findUnwindSectionsByPhdr(struct dl_phdr_info *pinfo,
                                    size_t pinfo_size, void *data) {
  auto cbdata = static_cast<dl_iterate_cb_data *>(data);
  if (pinfo->dlpi_phnum == 0)
    return 0;
  if (cbdata->targetAddr < pinfo->dlpi_addr) {
    CHERI_DBG("0x%jx out of bounds of %#p (%s)\n",
              (uintmax_t)cbdata->targetAddr.address(), (void *)pinfo->dlpi_addr,
              PINFO_NAME(pinfo));
    return 0;
  }
#if defined(_LIBUNWIND_USE_FRAME_HEADER_CACHE)
  if (TheFrameHeaderCache.find(pinfo, pinfo_size, data))
    return 1;
#else
  // Avoid warning about unused variable.
  (void)pinfo_size;
#endif

  uintptr_t image_base = calculateImageBase(pinfo);
#ifdef __CHERI_PURE_CAPABILITY__
  check_same_type<__uintcap_t, decltype(pinfo->dlpi_addr)>();
  check_same_type<const Elf_Phdr *, decltype(pinfo->dlpi_phdr)>();

  // Cannot use CTestSubset here because the dpli_addr perms are a strict
  // subset that never includes execute and so won't match targetAddr
  // which is always executable.
  //
  // TODO: __builtin_cheri_top_get_would be nice
  if (__builtin_cheri_length_get((void *)image_base) +
          __builtin_cheri_base_get((void *)image_base) <
      cbdata->targetAddr) {
    CHERI_DBG("%#p out of bounds of %#p (%s)\n",
              (void *)cbdata->targetAddr.get(), (void *)image_base,
              PINFO_NAME(pinfo));
    return false;
  }
#endif
  CHERI_DBG("Checking %s for target 0x%jx (%#p). Base=%#p\n", PINFO_NAME(pinfo),
            (uintmax_t)cbdata->targetAddr.address(),
            (void *)cbdata->targetAddr.get(), (void *)image_base);
#ifdef __CHERI_PURE_CAPABILITY__
  assert(cbdata->targetAddr.isValid());
  if (!__builtin_cheri_tag_get((void *)image_base)) {
    _LIBUNWIND_ABORT("image_base was untagged. CheriBSD needs to be updated!");
  }
#endif

  // Most shared objects seen in this callback function likely don't contain the
  // target address, so optimize for that. Scan for a matching PT_LOAD segment
  // first and bail when it isn't found.
  bool found_text = false;
  for (Elf_Half i = 0; i < pinfo->dlpi_phnum; ++i) {
    if (checkAddrInSegment(&pinfo->dlpi_phdr[i], image_base, cbdata)) {
      found_text = true;
      break;
    }
  }
  if (!found_text)
    return 0;

  // PT_GNU_EH_FRAME and PT_ARM_EXIDX are usually near the end. Iterate
  // backward.
  bool found_unwind = false;
  for (Elf_Half i = pinfo->dlpi_phnum; i > 0; i--) {
    const Elf_Phdr *phdr = &pinfo->dlpi_phdr[i - 1];
    if (checkForUnwindInfoSegment(phdr, image_base, cbdata)) {
      found_unwind = true;
      break;
    }
  }
  if (!found_unwind) {
    CHERI_DBG("Could not find EHDR in %s\n", PINFO_NAME(pinfo));
    return 0;
  }

  CHERI_DBG("found_text && found_unwind in %s\n", PINFO_NAME(pinfo));
  // Find the PT_LOAD containing .eh_frame.
  if (!boundEhFrameFromPhdr(pinfo, image_base, cbdata)) {
    return 0;
  }
#if defined(_LIBUNWIND_USE_FRAME_HEADER_CACHE)
  TheFrameHeaderCache.add(cbdata->sects);
#endif
  return 1;
}

#endif  // defined(_LIBUNWIND_USE_DL_ITERATE_PHDR)


inline bool LocalAddressSpace::findUnwindSections(pc_t targetAddr,
                                                  UnwindInfoSections &info) {
#ifdef __APPLE__
  dyld_unwind_sections dyldInfo;
  if (_dyld_find_unwind_sections(targetAddr.get(), &dyldInfo)) {
    info.dso_base                      = (uintptr_t)dyldInfo.mh;
 #if defined(_LIBUNWIND_SUPPORT_DWARF_UNWIND)
    info.set_dwarf_section((uintptr_t)dyldInfo.dwarf_section);
    info.dwarf_section_length          = (size_t)dyldInfo.dwarf_section_length;
 #endif
    info.compact_unwind_section        = (uintptr_t)dyldInfo.compact_unwind_section;
    info.compact_unwind_section_length = (size_t)dyldInfo.compact_unwind_section_length;
    return true;
  }
#elif defined(_LIBUNWIND_SUPPORT_DWARF_UNWIND) && defined(_LIBUNWIND_IS_BAREMETAL)
  info.dso_base = 0;
  // Bare metal is statically linked, so no need to ask the dynamic loader
  info.dwarf_section_length = (size_t)(&__eh_frame_end - &__eh_frame_start);
  info.dwarf_section =        (uintptr_t)(&__eh_frame_start);
  _LIBUNWIND_TRACE_UNWINDING("findUnwindSections: section %p length %p",
                             (void *)info.dwarf_section, (void *)info.dwarf_section_length);
#if defined(_LIBUNWIND_SUPPORT_DWARF_INDEX)
  info.dwarf_index_section =        (uintptr_t)(&__eh_frame_hdr_start);
  info.dwarf_index_section_length = (size_t)(&__eh_frame_hdr_end - &__eh_frame_hdr_start);
  _LIBUNWIND_TRACE_UNWINDING("findUnwindSections: index section %p length %p",
                             (void *)info.dwarf_index_section, (void *)info.dwarf_index_section_length);
#endif
  if (info.dwarf_section_length)
    return true;
#elif defined(_LIBUNWIND_ARM_EHABI) && defined(_LIBUNWIND_IS_BAREMETAL)
  // Bare metal is statically linked, so no need to ask the dynamic loader
  info.arm_section =        (uintptr_t)(&__exidx_start);
  info.arm_section_length = (size_t)(&__exidx_end - &__exidx_start);
  _LIBUNWIND_TRACE_UNWINDING("findUnwindSections: section %p length %p",
                             (void *)info.arm_section, (void *)info.arm_section_length);
  if (info.arm_section && info.arm_section_length)
    return true;
#elif defined(_LIBUNWIND_SUPPORT_DWARF_UNWIND) && defined(_WIN32)
  HMODULE mods[1024];
  HANDLE process = GetCurrentProcess();
  DWORD needed;

  if (!EnumProcessModules(process, mods, sizeof(mods), &needed)) {
    DWORD err = GetLastError();
    _LIBUNWIND_TRACE_UNWINDING("findUnwindSections: EnumProcessModules failed, "
                               "returned error %d", (int)err);
    return false;
  }

  for (unsigned i = 0; i < (needed / sizeof(HMODULE)); i++) {
    PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)mods[i];
    PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((BYTE *)pidh + pidh->e_lfanew);
    PIMAGE_FILE_HEADER pifh = (PIMAGE_FILE_HEADER)&pinh->FileHeader;
    PIMAGE_SECTION_HEADER pish = IMAGE_FIRST_SECTION(pinh);
    bool found_obj = false;
    bool found_hdr = false;

    info.dso_base = (uintptr_t)mods[i];
    for (unsigned j = 0; j < pifh->NumberOfSections; j++, pish++) {
      uintptr_t begin = pish->VirtualAddress + (uintptr_t)mods[i];
      uintptr_t end = begin + pish->Misc.VirtualSize;
      if (!strncmp((const char *)pish->Name, ".text",
                   IMAGE_SIZEOF_SHORT_NAME)) {
        if (targetAddr >= begin && targetAddr < end)
          found_obj = true;
      } else if (!strncmp((const char *)pish->Name, ".eh_frame",
                          IMAGE_SIZEOF_SHORT_NAME)) {
        info.dwarf_section = begin;
        info.dwarf_section_length = pish->Misc.VirtualSize;
        found_hdr = true;
      }
      if (found_obj && found_hdr)
        return true;
    }
  }
  return false;
#elif defined(_LIBUNWIND_SUPPORT_SEH_UNWIND) && defined(_WIN32)
  // Don't even bother, since Windows has functions that do all this stuff
  // for us.
  (void)targetAddr;
  (void)info;
  return true;
#elif defined(_LIBUNWIND_USE_DL_UNWIND_FIND_EXIDX)
  int length = 0;
  info.arm_section =
      (uintptr_t)dl_unwind_find_exidx((_Unwind_Ptr)targetAddr, &length);
  info.arm_section_length = (size_t)length * sizeof(EHABIIndexEntry);
  if (info.arm_section && info.arm_section_length)
    return true;
#elif defined(_LIBUNWIND_USE_DL_ITERATE_PHDR)
  dl_iterate_cb_data cb_data = {this, &info, targetAddr};
  CHERI_DBG("Calling dl_iterate_phdr()\n");
  int found = dl_iterate_phdr(findUnwindSectionsByPhdr, &cb_data);
  return static_cast<bool>(found);
#endif

  return false;
}


inline bool LocalAddressSpace::findOtherFDE(addr_t targetAddr, pint_t &fde) {
  // TO DO: if OS has way to dynamically register FDEs, check that.
  (void)targetAddr;
  (void)fde;
  return false;
}

inline bool LocalAddressSpace::findFunctionName(pc_t ip, char *buf,
                                                size_t bufLen,
                                                unw_word_t *offset) {
#if _LIBUNWIND_USE_DLADDR
  Dl_info dyldInfo;
  CHERI_DBG("%s(0x%jx: %#p))\n", __func__, (uintmax_t)ip.address(),
            (void *)ip.get());
  if (dladdr((void *)ip.get(), &dyldInfo)) {
    if (dyldInfo.dli_sname != NULL) {
      snprintf(buf, bufLen, "%s", dyldInfo.dli_sname);
      *offset = ip.address() - (__cheri_addr addr_t)dyldInfo.dli_saddr;
      return true;
    } else if (dyldInfo.dli_fname != NULL) {
      snprintf(buf, bufLen, "%s", dyldInfo.dli_fname);
      *offset = ip.address() - (__cheri_addr addr_t)dyldInfo.dli_fbase;
      return true;
    }
  }
#else
  (void)ip;
  (void)buf;
  (void)bufLen;
  (void)offset;
#endif
  return false;
}

} // namespace libunwind

#endif // __ADDRESSSPACE_HPP__

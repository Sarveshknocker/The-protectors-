# Compiler/linker hardening for C/C++ firmware and native code (GCC / Clang).
# include(cmake/hardening-flags.cmake) then: protectors_harden(<target>)
# Embedded notes: PIE/RELRO/NX don't apply to most bare-metal MCUs — use the MPU (no-exec RAM, stack guard) instead.

function(protectors_harden target)
  target_compile_options(${target} PRIVATE
    -Wall -Wextra -Wformat=2 -Werror=format-security -Wshadow -Wconversion -Wvla
    -Werror=implicit-function-declaration
    -fstack-protector-strong
    -fno-strict-overflow -fno-delete-null-pointer-checks
    $<$<CONFIG:Release,MinSizeRel,RelWithDebInfo>:-D_FORTIFY_SOURCE=2>
    $<$<CONFIG:Release,MinSizeRel>:-DNDEBUG>
  )

  # Hosted Linux targets (gateways, Yocto/Buildroot user space):
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set_target_properties(${target} PROPERTIES POSITION_INDEPENDENT_CODE ON)
    target_compile_options(${target} PRIVATE -fstack-clash-protection -fcf-protection=full)
    target_link_options(${target} PRIVATE -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)
  endif()
endfunction()

# Host-side fuzzing of parsers (build the parser for x86 and run under libFuzzer):
#   add_executable(fuzz_parser tests/fuzz_parser.c src/parser.c)
#   target_compile_options(fuzz_parser PRIVATE -g -O1 -fsanitize=fuzzer,address,undefined)
#   target_link_options(fuzz_parser PRIVATE -fsanitize=fuzzer,address,undefined)

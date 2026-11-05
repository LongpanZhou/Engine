// safe windows wrappers and helper functions for extended functionality
#ifndef WDK_WINDOWS_HPP
#define WDK_WINDOWS_HPP
#include "../arch/arch.hpp"
#include "declarations.hpp"

namespace win {
    template <typename T1, typename T2, typename... Ts>
    requires utils::is_enum_or_integral<T1> && utils::is_enum_or_integral<T2>
    ALWAYS_INLINE ntstatus
    print_ex(T1 component_id, T2 level, const char* fmt, Ts&&... args) {
            return DbgPrintEx(static_cast<std::uint32_t>(component_id),
                              static_cast<std::uint32_t>(level),
                              fmt, std::forward<Ts>(args)...);
        }
} // namespace win

#endif // WDK_WINDOWS_HPP

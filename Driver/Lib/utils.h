#pragma once
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wnested-anon-types"
#pragma clang diagnostic ignored "-Wgnu-anonymous-struct"

// Log tags: prefixes for print()
#define INFO(msg)	"[*]" msg "\n"
#define OK(msg)		"[+]" msg "\n"
#define WARN(msg)	"[!]" msg "\n"
#define ERROR(msg)	"[-]" msg "\n"


// print() compiles to nothing in release builds
#ifdef DEBUG
template <typename... T>
__forceinline void print(const char* fmt, T... args)
{
    win::print_ex(0, 0, fmt, args...);
}
#else
template <typename... T>
__forceinline void print(const char*, T...)
{
}
#endif
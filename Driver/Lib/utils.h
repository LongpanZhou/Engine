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


// print() compiles to nothing in release builds.
//
// Release uses a preprocessor discard, not an empty variadic template. The template
// still parses and passes every format literal, and some builds keep those literals
// in .rdata even when the call is inlined away. The macro removes the whole call
// before the compiler sees it, so no debug format string can survive a release.
#ifdef DEBUG
template <typename... T>
__forceinline void print(const char* fmt, T... args)
{
    win::print_ex(0, 0, fmt, args...);
}
#else
#define print(...) ((void)0)
#endif
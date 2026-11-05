// Client-only entry point: links PostboxClient.cpp without the removed legacy
// shared-memory client. This is the product client binary.
#include <windows.h>

int PostboxClientMain(int argc, char** argv);

int main(int argc, char** argv)
{
    return PostboxClientMain(argc, argv);
}

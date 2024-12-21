#include "Decoder.h"

int main(int argc, char *argv[]) {
    // Flush after every std::cout / std::cerr
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    if (!dispatchCommand(argc, argv)) {
        return 1;
    }
    return 0;
}

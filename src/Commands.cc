#include "Commands.h"

namespace {
void hexdump(const std::string &str) {
    std::ios state(nullptr);
    state.copyfmt(std::cerr);

    for (size_t i = 0; i < str.length(); ++i) {
        if (i % 16 == 0) { // Print address at the beginning of each line
            std::cerr << std::hex << std::setw(8) << std::setfill('0') << i
                      << ": ";
        }

        std::cerr << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(str[i] & 0xff) << " ";

        if ((i + 1) % 16 == 0) {
            std::cerr << " "; // Separate hex and ASCII
            for (size_t j = i - 15; j <= i; ++j) {
                char c = str[j];
                std::cerr << (std::isprint(c) ? c : '.');
            }
            std::cerr << std::endl;
        }
    }

    if (str.length() % 16 != 0) { // Print last line if not complete
        for (size_t i = 0; i < 16 - (str.length() % 16); ++i) {
            std::cerr << "   ";
        }
        std::cerr << " ";
        for (size_t i = str.length() - (str.length() % 16); i < str.length();
             ++i) {
            char c = str[i];
            std::cerr << (std::isprint(c) ? c : '.');
        }
        std::cerr << std::endl;
    }

    std::cerr.copyfmt(state); // Restore the original state
}
} // namespace

void decodeTorrentFile(const std::string &file_path) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;

    std::ifstream file(file_path);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + file_path);
    }

    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    auto [decoded_value, sizeConsumed] = decodeBencodedValue(content);
    assert(("Entire string not consumed", sizeConsumed == content.size()));
    std::cout << "Tracker URL: " << decoded_value["announce"].get<std::string>()
              << std::endl;
    std::cout << "Length: " << decoded_value["info"]["length"].get<int>()
              << std::endl;

    SHA1 hasher;
    std::string info = encodeJson(decoded_value["info"]);
    hasher.update(info);
    std::cout << "Info Hash: " << hasher.final() << std::endl;
    std::cout << "Piece Length: "
              << decoded_value["info"]["piece length"].get<int>() << std::endl;

    std::string pieces_val = decoded_value["info"]["pieces"].get<std::string>();

    for (uint i = 0; i < pieces_val.size(); i += 20) {
        std::string piece_hash = pieces_val.substr(i, 20);
        std::ostringstream result;
        for (size_t i = 0; i < piece_hash.size() / sizeof(piece_hash[0]); i++) {
            result << std::hex << std::setfill('0') << std::setw(2)
                   << static_cast<int>(piece_hash[i] & 0xff);
        }
        std::cout << "Pieces: " << result.str() << std::endl;
    }
}

bool dispatchCommand(int argc, char *argv[]) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;

    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " decode <encoded_value>"
                  << std::endl;
        return false;
    }

    std::string command = argv[1];

    if (command == "decode") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " decode <encoded_value>"
                      << std::endl;
            return false;
        }
        std::string encoded_value = argv[2];
        auto [decoded_value, size_consumed] =
            decodeBencodedValue(encoded_value);
        assert(("Entire string not consumed",
                size_consumed == encoded_value.size()));
        std::cout << decoded_value.dump() << std::endl;
    } else if (command == "info") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " info <file_path>"
                      << std::endl;
            return false;
        }
        std::string file_path = argv[2];
        decodeTorrentFile(file_path);
    } else {
        std::cerr << "unknown command: " << command << std::endl;
        return false;
    }
    return true;
}
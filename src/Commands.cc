#include "Commands.h"
#include "lib/HTTPRequest.hpp"

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

std::string url_encode(const std::string &value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (char c : value) {
        // Keep alphanumeric and other accepted characters intact
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
            continue;
        }

        // Any other characters are percent-encoded
        escaped << std::uppercase;
        escaped << '%' << std::setw(2) << static_cast<int>(c & 0xff);
        escaped << std::nouppercase;
    }

    return escaped.str();
}

std::string hexToString(const std::string &hex) {
    std::string result;
    result.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        std::string byte = hex.substr(i, 2);
        char chr = char(std::stoi(byte, nullptr, 16));
        result += chr;
    }

    return result;
}

std::string formatUrlWithGetParams(
    const std::string &url,
    const std::unordered_map<std::string, std::string> &params) {
    if (params.empty()) {
        return url;
    }

    std::string formatted_url = url + "?";
    for (const auto &[key, value] : params) {
        formatted_url += key + "=" + url_encode(value) + "&";
    }
    formatted_url.pop_back(); // Remove the trailing '&'

    return formatted_url;
}

jsonWithSize getTorrentFileContents(const std::string &torrent_file_path) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;

    std::ifstream file(torrent_file_path);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + torrent_file_path);
    }

    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    jsonWithSize res = decodeBencodedValue(content);
    assert(("Entire string not consumed", res.second == content.size()));
    return res;
}

void decodeTorrentFile(const std::string &torrent_file_path) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;

    auto [decoded_value, sizeConsumed] =
        getTorrentFileContents(torrent_file_path);

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
    assert(("Invalid pieces value size", pieces_val.size() % 20 == 0));

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

void discoverPeers(const std::string &torrent_file_path) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;

    auto [decoded_value, sizeConsumed] =
        getTorrentFileContents(torrent_file_path);

    SHA1 hasher;
    hasher.update(encodeJson(decoded_value["info"]));

    std::unordered_map<std::string, std::string> params = {
        {"info_hash", hexToString(hasher.final())},
        {"peer_id", "-TR2940-0b0b0b0b0b0b"},
        {"port", "6881"},
        {"uploaded", "0"},
        {"downloaded", "0"},
        {"left", std::to_string(decoded_value["info"]["length"].get<int>())},
        {"compact", "1"}};

    std::string url = decoded_value["announce"].get<std::string>();
    std::string formatted_url = formatUrlWithGetParams(url, params);

    std::cerr << "Formatted URL: " << formatted_url << std::endl;

    http::Request request{formatted_url, http::InternetProtocol::v4};
    const auto response = request.send("GET");

    std::string respStr{response.body.begin(), response.body.end()};

    jsonWithSize respDecoded = decodeBencodedValue(respStr);
    assert(
        ("Entire string not consumed", respDecoded.second == respStr.size()));
    std::string peers = respDecoded.first["peers"].get<std::string>();
    assert(("Invalid peers value size", peers.size() % 6 == 0));

    for (uint i = 0; i < peers.size(); i += 6) {
        std::string ip = std::to_string(peers[i] & 0xff) + "." +
                         std::to_string(peers[i + 1] & 0xff) + "." +
                         std::to_string(peers[i + 2] & 0xff) + "." +
                         std::to_string(peers[i + 3] & 0xff);
        uint16_t port = (peers[i + 4] & 0xff) << 8 | (peers[i + 5] & 0xff);
        std::cout << ip << ":" << port << std::endl;
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
        std::string torrent_file_path = argv[2];
        decodeTorrentFile(torrent_file_path);
    } else if (command == "peers") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " peers <file_path>"
                      << std::endl;
            return false;
        }
        std::string torrent_file_path = argv[2];
        discoverPeers(torrent_file_path);
    } else {
        std::cerr << "unknown command: " << command << std::endl;
        return false;
    }
    return true;
}
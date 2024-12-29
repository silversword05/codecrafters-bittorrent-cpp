#include "Commands.h"
#include "lib/HTTPRequest.hpp"
#include "lib/argparse/argparse.hpp"
#include <arpa/inet.h>

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

std::string urlEncode(const std::string &value) {
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

std::string stringToHex(const std::string &str) {
    std::ostringstream result;
    for (size_t i = 0; i < str.size() / sizeof(str[0]); i++) {
        result << std::hex << std::setfill('0') << std::setw(2)
               << static_cast<int>(str[i] & 0xff);
    }
    return result.str();
}

std::string formatUrlWithGetParams(
    const std::string &url,
    const std::unordered_map<std::string, std::string> &params) {
    if (params.empty()) {
        return url;
    }

    std::string formatted_url = url + "?";
    for (const auto &[key, value] : params) {
        formatted_url += key + "=" + urlEncode(value) + "&";
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
        std::cout << "Pieces: " << stringToHex(piece_hash) << std::endl;
    }
}

std::vector<IPPort> getPeers(const std::string &torrent_file_path) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;

    auto [decoded_value, sizeConsumed] =
        getTorrentFileContents(torrent_file_path);

    SHA1 hasher;
    hasher.update(encodeJson(decoded_value["info"]));

    std::unordered_map<std::string, std::string> params = {
        {"info_hash", hexToString(hasher.final())},
        {"peer_id", PEER_ID},
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

    std::vector<IPPort> result;
    for (uint i = 0; i < peers.size(); i += 6) {
        std::string ip = std::to_string(peers[i] & 0xff) + "." +
                         std::to_string(peers[i + 1] & 0xff) + "." +
                         std::to_string(peers[i + 2] & 0xff) + "." +
                         std::to_string(peers[i + 3] & 0xff);
        uint16_t port = (peers[i + 4] & 0xff) << 8 | (peers[i + 5] & 0xff);
        result.push_back({ip, port});
    }

    return result;
}

void discoverPeers(const std::string &torrent_file_path) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;

    std::vector<IPPort> peers = getPeers(torrent_file_path);
    for (const auto &peer : peers) {
        std::cout << peer.first << ":" << peer.second << std::endl;
    }
}

std::string getHandshakeBuffer(const std::string &torrent_file_path) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;

    auto [decoded_value, sizeConsumed] =
        getTorrentFileContents(torrent_file_path);

    SHA1 hasher;
    hasher.update(encodeJson(decoded_value["info"]));

    std::string info_hash = hexToString(hasher.final());

    std::string handshake;
    std::string protocol = "BitTorrent protocol";
    handshake.push_back(static_cast<char>(protocol.size()));
    handshake.append(protocol);
    handshake.append(8, 0);

    handshake += info_hash;
    handshake += PEER_ID;

    return handshake;
}

void doHandshake(const std::string &torrent_file_path, const IPPort &peer) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;

    struct sockaddr_in serv_addr;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket failed: ");
        throw std::runtime_error("Failed to create server socket: ");
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(peer.second);

    if (inet_pton(AF_INET, peer.first.c_str(), &serv_addr.sin_addr) <= 0) {
        perror("inet_pton failed: ");
        throw std::runtime_error("Invalid address/ Address not supported: ");
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect failed: ");
        throw std::runtime_error("Connection failed: ");
    }

    std::string handshake = getHandshakeBuffer(torrent_file_path);
    hexdump(handshake);

    if (send(sock, handshake.c_str(), handshake.size(), 0) < 0) {
        perror("send failed: ");
        throw std::runtime_error("Failed to send handshake: ");
    }

    char buffer[MAX_BUFFER_SIZE] = {0};
    int valread = read(sock, buffer, MAX_BUFFER_SIZE);
    if (valread < 0) {
        perror("read failed: ");
        throw std::runtime_error("Failed to read from socket: ");
    }
    std::string output(buffer, valread);
    hexdump(output);

    std::string peer_id = output.substr(48, 20);
    std::cout << "Peer ID: " << stringToHex(peer_id) << std::endl;
}

void dispatchCommand(int argc, char *argv[]) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;

    argparse::ArgumentParser program("bittorrent");

    argparse::ArgumentParser decode_command("decode");
    decode_command.add_description("Decode a bencoded value.");
    decode_command.add_argument("encoded_value")
        .help("The encoded value to decode.")
        .required();
    program.add_subparser(decode_command);

    argparse::ArgumentParser info_command("info");
    info_command.add_description("Get information about a torrent file.");
    info_command.add_argument("file_path")
        .help("The path to the torrent file.")
        .required();
    program.add_subparser(info_command);

    argparse::ArgumentParser peers_command("peers");
    peers_command.add_description("Get the list of peers for a torrent file.");
    peers_command.add_argument("file_path")
        .help("The path to the torrent file.")
        .required();
    program.add_subparser(peers_command);

    argparse::ArgumentParser handshake_command("handshake");
    handshake_command.add_description("Perform a handshake with a peer.");
    handshake_command.add_argument("file_path")
        .help("The path to the torrent file.")
        .required();
    handshake_command.add_argument("peer")
        .help("The peer to handshake with.")
        .required();
    program.add_subparser(handshake_command);

    program.parse_args(argc, argv);

    if (program.is_subcommand_used("decode")) {
        std::string encoded_value =
            decode_command.get<std::string>("encoded_value");
        auto [decoded_value, size_consumed] =
            decodeBencodedValue(encoded_value);
        assert(("Entire string not consumed",
                size_consumed == encoded_value.size()));
        std::cout << decoded_value.dump() << std::endl;
    } else if (program.is_subcommand_used("info")) {
        std::string torrent_file_path =
            info_command.get<std::string>("file_path");
        decodeTorrentFile(torrent_file_path);
    } else if (program.is_subcommand_used("peers")) {
        std::string torrent_file_path =
            peers_command.get<std::string>("file_path");
        discoverPeers(torrent_file_path);
    } else if (program.is_subcommand_used("handshake")) {
        std::string torrent_file_path =
            handshake_command.get<std::string>("file_path");
        std::string peer_str = handshake_command.get<std::string>("peer");
        size_t colon_pos = peer_str.find(':');
        if (colon_pos == std::string::npos) {
            throw std::runtime_error("Invalid peer address");
        }
        std::string ip = peer_str.substr(0, colon_pos);
        uint16_t port = std::stoi(peer_str.substr(colon_pos + 1));
        IPPort peer = {ip, port};
        doHandshake(torrent_file_path, peer);
    }
}
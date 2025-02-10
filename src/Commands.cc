#include "Commands.h"
#include "PieceMessages.h"
#include "lib/HTTPRequest.hpp"
#include "lib/argparse/argparse.hpp"

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

std::string urlDecode(const std::string &value) {
    std::ostringstream unescaped;
    unescaped.fill('0');
    unescaped << std::hex;

    for (size_t i = 0; i < value.size(); i++) {
        char c = value[i];
        if (c == '%') {
            if (i + 2 >= value.size()) {
                throw std::runtime_error("Invalid URL encoding");
            }
            i++;
            int hex_val = std::stoi(value.substr(i, 2), nullptr, 16);
            unescaped << static_cast<char>(hex_val);
            i++;
        } else {
            unescaped << c;
        }
    }

    return unescaped.str();
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

std::string getInfoHash(const std::string &torrent_file_path) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;
    auto [decoded_value, sizeConsumed] =
        getTorrentFileContents(torrent_file_path);
    SHA1 hasher;
    hasher.update(encodeJson(decoded_value["info"]));
    return hexToString(hasher.final());
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

std::vector<IPPort> getPeers(const std::string &info_hash,
                             const std::string &tracker_url, const int left) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;

    std::unordered_map<std::string, std::string> params = {
        {"info_hash", info_hash}, {"peer_id", PEER_ID},
        {"port", "6881"},         {"uploaded", "0"},
        {"downloaded", "0"},      {"left", std::to_string(left)},
        {"compact", "1"}};

    std::string formatted_url = formatUrlWithGetParams(tracker_url, params);
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

std::vector<IPPort> getPeers(const json &decoded_value) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;

    SHA1 hasher;
    hasher.update(encodeJson(decoded_value["info"]));
    return getPeers(hexToString(hasher.final()),
                    decoded_value["announce"].get<std::string>(),
                    decoded_value["info"]["length"].get<int>());
}

void discoverPeers(const std::string &torrent_file_path) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;

    auto [decoded_value, sizeConsumed] =
        getTorrentFileContents(torrent_file_path);
    std::vector<IPPort> peers = getPeers(decoded_value);
    for (const auto &peer : peers) {
        std::cout << peer.first << ":" << peer.second << std::endl;
    }
}

std::string getHandshakeBuffer(const std::string &info_hash,
                               bool support_extension) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;
    std::string handshake;
    std::string protocol = "BitTorrent protocol";
    handshake.push_back(static_cast<char>(protocol.size()));
    handshake.append(protocol);
    handshake.append(8, 0);

    if (support_extension) {
        handshake[handshake.size() - 3] = 0x10;
    }

    handshake += info_hash;
    handshake += PEER_ID;

    return handshake;
}

std::pair<std::string, bool> doHandshakeHelper(const std::string &info_hash,
                                               const TCPHandler &tcp_handler,
                                               bool support_extension) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;

    std::string handshake = getHandshakeBuffer(info_hash, support_extension);
    tcp_handler.sendData(handshake);
    std::string output = tcp_handler.readHandShake();
    std::string peer_id = output.substr(48, 20);
    bool reserved = output[25] & 0x10;
    return {peer_id, reserved};
}

void doHandshake(const std::string &torrent_file_path, const IPPort &peer) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;

    TCPHandler tcp_handler(peer);
    auto [peer_id, _] =
        doHandshakeHelper(getInfoHash(torrent_file_path), tcp_handler, false);
    std::cout << "Peer ID: " << stringToHex(peer_id) << std::endl;
}

bool verifyPeice(const std::string &piece, const std::string &piece_hash) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;

    SHA1 hasher;
    hasher.update(piece);
    return hexToString(hasher.final()) == piece_hash;
}

void downloadPiece(const std::string &torrent_file_path,
                   const std::string &output_file_path,
                   const uint32_t piece_index) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;

    auto [decoded_value, sizeConsumed] =
        getTorrentFileContents(torrent_file_path);
    std::vector<IPPort> peers = getPeers(decoded_value);
    assert(("No peers found", !peers.empty()));

    auto tcp_handler = std::make_unique<TCPHandler>(peers[0]);
    doHandshakeHelper(getInfoHash(torrent_file_path), *tcp_handler, false);

    std::string message = tcp_handler->readMessage();
    Message parsed_message = Message::parseFromBuffer(message);
    assert(("Not a bitfield message",
            parsed_message.type == MessageType::BITFIELD));

    tcp_handler->sendData(Message::getInterestedMessage());
    while (!Message::isUnchokeMessage(tcp_handler->readMessage())) {
        continue;
    }

    PieceDownloader piece_downloader(decoded_value, std::move(tcp_handler));
    std::string piece_data = piece_downloader.downloadPiece(piece_index);

    std::ofstream output_file(output_file_path, std::ios::binary);
    output_file.write(piece_data.data(), piece_data.size());

    std::string pieces_val = decoded_value["info"]["pieces"].get<std::string>();
    assert(("Invalid pieces value size", pieces_val.size() % 20 == 0));
    std::string piece_hash = pieces_val.substr(piece_index * 20, 20);
    assert(("Piece verification failed", verifyPeice(piece_data, piece_hash)));

    std::cerr << "Piece downloaded successfully" << std::endl;
}

void download(const std::string &torrent_file_path,
              const std::string &output_file_path) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;

    auto [decoded_value, sizeConsumed] =
        getTorrentFileContents(torrent_file_path);
    std::vector<IPPort> peers = getPeers(decoded_value);
    assert(("No peers found", !peers.empty()));

    std::vector<PieceDownloader> piece_downloaders(peers.size());
    auto prepare_downloader = [&](size_t peer_index) {
        auto tcp_handler = std::make_unique<TCPHandler>(peers[peer_index]);
        doHandshakeHelper(getInfoHash(torrent_file_path), *tcp_handler, false);

        std::string message = tcp_handler->readMessage();
        Message parsed_message = Message::parseFromBuffer(message);
        assert(("Not a bitfield message",
                parsed_message.type == MessageType::BITFIELD));

        tcp_handler->sendData(Message::getInterestedMessage());
        while (!Message::isUnchokeMessage(tcp_handler->readMessage())) {
            continue;
        }

        piece_downloaders[peer_index] =
            PieceDownloader(decoded_value, std::move(tcp_handler));
    };

    {
        std::vector<std::jthread> threads;
        for (size_t peer_index = 0; peer_index < peers.size(); peer_index++) {
            threads.emplace_back(prepare_downloader, peer_index);
        }
    }
    std::cerr << "All peer connections established" << std::endl;

    std::string pieces_val = decoded_value["info"]["pieces"].get<std::string>();
    assert(("Invalid pieces value size", pieces_val.size() % 20 == 0));
    std::vector<std::string> pieces_data(pieces_val.size() / 20);

    auto peer_downloader = [&](size_t peer_index) {
        uint32_t piece_index = peer_index;
        while (piece_index < pieces_val.size() / 20) {
            pieces_data[piece_index] =
                piece_downloaders[peer_index].downloadPiece(piece_index);
            std::string piece_hash = pieces_val.substr(piece_index * 20, 20);
            assert(("Piece verification failed",
                    verifyPeice(pieces_data[piece_index], piece_hash)));
            std::cerr << "Piece " << piece_index
                      << " downloaded successfully by peer " << peer_index
                      << std::endl;
            piece_index += peers.size();
        }
    };

    {
        std::vector<std::jthread> threads;
        for (size_t peer_index = 0; peer_index < peers.size(); peer_index++) {
            threads.emplace_back(peer_downloader, peer_index);
        }
    }

    std::ofstream output_file(output_file_path, std::ios::binary);
    for (uint32_t i = 0; i < pieces_val.size() / 20; i++) {
        const std::string &piece_data = pieces_data[i];
        output_file.write(piece_data.data(), piece_data.size());
    }
    std::cerr << "Download completed successfully" << std::endl;
}

std::unordered_map<std::string, std::string>
parseMagnetLink(const std::string &magnet_link) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;

    std::string prefix = "magnet:?";
    if (magnet_link.substr(0, prefix.size()) != prefix) {
        throw std::runtime_error("Invalid magnet link");
    }

    std::string params_str = urlDecode(magnet_link.substr(prefix.size()));
    auto params_args = params_str | std::views::split('&');
    std::unordered_map<std::string, std::string> params;

    std::ranges::for_each(params_args, [&params](auto &&arg) {
        std::string_view sarg(arg.begin(), arg.end());
        std::string::size_type eq_pos = sarg.find('=');
        if (eq_pos == std::string::npos) {
            throw std::runtime_error("Invalid magnet link");
        }
        std::string key(sarg.substr(0, eq_pos));
        std::string value(sarg.substr(eq_pos + 1));
        params[key] = value;
    });

    return params;
}

void printMagnetLinkInfo(const std::string &magnet_link) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;

    std::unordered_map<std::string, std::string> params =
        parseMagnetLink(magnet_link);
    std::cout << "Tracker URL: " << params["tr"] << std::endl;
    std::cout << "Info Hash: " << params["xt"].substr(9) << std::endl;
}

void doExtendedHandshake(const TCPHandler &tcp_handler) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;

    std::string message = tcp_handler.readMessage();
    Message parsed_message = Message::parseFromBuffer(message);
    assert(("Not a extended handshake message",
            parsed_message.type == MessageType::BT_EXTENDED));

    tcp_handler.sendData(Message::getExtenedHandshakeMessage());
}

void magnetHandshake(const std::string &magnet_link) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;

    std::unordered_map<std::string, std::string> params =
        parseMagnetLink(magnet_link);
    std::string info_hash = params["xt"].substr(9);
    std::string tracker_url = params["tr"];

    std::vector<IPPort> peers =
        getPeers(hexToString(info_hash), tracker_url, 999);
    assert(("No peers found", !peers.empty()));

    TCPHandler tcp_handler(peers[0]);
    auto [peer_id, reserved] =
        doHandshakeHelper(hexToString(info_hash), tcp_handler, true);

    std::string message = tcp_handler.readMessage();
    Message parsed_message = Message::parseFromBuffer(message);
    assert(("Not a bitfield message",
            parsed_message.type == MessageType::BITFIELD));

    if (reserved) {
        doExtendedHandshake(tcp_handler);
    }

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

    argparse::ArgumentParser download_piece_command("download_piece");
    download_piece_command.add_description("Download a piece from a peer.");
    download_piece_command.add_argument("-o", "--output")
        .help("The output file path.")
        .required();
    download_piece_command.add_argument("file_path")
        .help("The path to the torrent file.")
        .required();
    download_piece_command.add_argument("piece_index")
        .help("The peice index to download.")
        .scan<'i', uint32_t>()
        .required();
    program.add_subparser(download_piece_command);

    argparse::ArgumentParser download_command("download");
    download_command.add_description("Download a torrent file.");
    download_command.add_argument("-o", "--output")
        .help("The output file path.")
        .required();
    download_command.add_argument("file_path")
        .help("The path to the torrent file.")
        .required();
    program.add_subparser(download_command);

    argparse::ArgumentParser magnet_parse_command("magnet_parse");
    magnet_parse_command.add_description("Parse a magnet link.");
    magnet_parse_command.add_argument("magnet_link")
        .help("The magnet link to parse.")
        .required();
    program.add_subparser(magnet_parse_command);

    argparse::ArgumentParser magnet_handshake_command("magnet_handshake");
    magnet_handshake_command.add_description("Perform a handshake with a peer "
                                             "using a magnet link.");
    magnet_handshake_command.add_argument("magnet_link")
        .help("The magnet link to use.")
        .required();
    program.add_subparser(magnet_handshake_command);

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
    } else if (program.is_subcommand_used("download_piece")) {
        std::string output_file_path =
            download_piece_command.get<std::string>("output");
        std::string torrent_file_path =
            download_piece_command.get<std::string>("file_path");
        uint32_t piece_index =
            download_piece_command.get<uint32_t>("piece_index");
        downloadPiece(torrent_file_path, output_file_path, piece_index);
    } else if (program.is_subcommand_used("download")) {
        std::string output_file_path =
            download_command.get<std::string>("output");
        std::string torrent_file_path =
            download_command.get<std::string>("file_path");
        download(torrent_file_path, output_file_path);
    } else if (program.is_subcommand_used("magnet_parse")) {
        std::string magnet_link =
            magnet_parse_command.get<std::string>("magnet_link");
        printMagnetLinkInfo(magnet_link);
    } else if (program.is_subcommand_used("magnet_handshake")) {
        std::string magnet_link =
            magnet_handshake_command.get<std::string>("magnet_link");
        magnetHandshake(magnet_link);
    }
}
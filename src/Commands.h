#pragma once

#include "Decoder.h"
#include "Encoder.h"

using IPPort = std::pair<std::string, uint16_t>;
static constexpr size_t MAX_BUFFER_SIZE = 1024;
static const std::string PEER_ID = "-TR2940-0b0b0b0b0b0b";

std::string urlEncode(const std::string &value);
std::string formatUrlWithGetParams(
    const std::string &url,
    const std::unordered_map<std::string, std::string> &params);

std::string hexToString(const std::string &hex);
std::string stringToHex(const std::string &str);

jsonWithSize getTorrentFileContents(const std::string &torrent_file_path);
void decodeTorrentFile(const std::string &torrent_file_path);

std::vector<IPPort> getPeers(const std::string &torrent_file_path);
void discoverPeers(const std::string &torrent_file_path);

std::string getHandshakeBuffer(const std::string &torrent_file_path);
void doHandshake(const std::string &torrent_file_path, const IPPort &peer);

bool dispatchCommand(int argc, char *argv[]);
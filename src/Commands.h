#pragma once

#include "Decoder.h"
#include "Encoder.h"

std::string url_encode(const std::string &value);
std::string formatUrlWithGetParams(
    const std::string &url,
    const std::unordered_map<std::string, std::string> &params);
std::string hexToString(const std::string &hex);

jsonWithSize getTorrentFileContents(const std::string &torrent_file_path);
void decodeTorrentFile(const std::string &torrent_file_path);
void discoverPeers(const std::string &torrent_file_path);
bool dispatchCommand(int argc, char *argv[]);
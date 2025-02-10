#pragma once

#include "Decoder.h"
#include "Encoder.h"
#include "TCPHandler.h"

static const std::string PEER_ID = "-TR2940-0b0b0b0b0b0b";

std::string urlEncode(const std::string &value);
std::string urlDecode(const std::string &value);

std::string hexToString(const std::string &hex);
std::string stringToHex(const std::string &str);

std::string formatUrlWithGetParams(
    const std::string &url,
    const std::unordered_map<std::string, std::string> &params);
std::string getInfoHash(const std::string &torrent_file_path);

jsonWithSize getTorrentFileContents(const std::string &torrent_file_path);
void decodeTorrentFile(const std::string &torrent_file_path);

std::vector<IPPort> getPeers(const std::string &info_hash,
                             const std::string &tracker_url, const int left);
std::vector<IPPort> getPeers(const json &decoded_value);
void discoverPeers(const std::string &torrent_file_path);

std::string getHandshakeBuffer(const std::string &info_hash,
                               bool support_extension);
std::pair<std::string, bool> doHandshakeHelper(const std::string &info_hash,
                                               const TCPHandler &tcp_handler,
                                               bool support_extension);
void doHandshake(const std::string &torrent_file_path, const IPPort &peer);

bool verifyPeice(const std::string &piece, const std::string &piece_hash);
void downloadPiece(const std::string &torrent_file_path,
                   const std::string &output_file_path,
                   const uint32_t piece_index);

void download(const std::string &torrent_file_path,
              const std::string &output_file_path);

std::unordered_map<std::string, std::string>
parseMagnetLink(const std::string &magnet_link);

json doExtendedHandshake(const TCPHandler &tcp_handler);

void printMagnetLinkInfo(const std::string &magnet_link);
void magnetHandshake(const std::string &magnet_link);

void dispatchCommand(int argc, char *argv[]);
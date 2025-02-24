#pragma once

#include "Decoder.h"
#include "Encoder.h"
#include "TCPHandler.h"

static const std::string PEER_ID = "-TR2940-0b0b0b0b0b0b";

struct Commands {
  public:
    static void decodeTorrentFile(const std::string &torrent_file_path);
    static void discoverPeers(const std::string &torrent_file_path);

    static void doHandshake(const std::string &torrent_file_path,
                            const IPPort &peer);

    static void downloadPiece(const std::string &torrent_file_path,
                              const std::string &output_file_path,
                              const uint32_t piece_index);

    static void download(const std::string &torrent_file_path,
                         const std::string &output_file_path);

    static void printMagnetLinkParse(const std::string &magnet_link);
    static void magnetHandshake(const std::string &magnet_link);
    static void printMagnetLinkInfo(const std::string &magnet_link);

    static void downloadMagentPiece(const std::string &magnet_link,
                                    const std::string &output_file_path,
                                    const uint32_t piece_index);

    static void downloadMagnent(const std::string &magnet_link,
                                const std::string &output_file_path);

  private:
    static std::string urlEncode(const std::string &value);
    static std::string urlDecode(const std::string &value);

    static std::string hexToString(const std::string &hex);
    static std::string stringToHex(const std::string &str);

    static std::string formatUrlWithGetParams(
        const std::string &url,
        const std::unordered_map<std::string, std::string> &params);
    static std::string getInfoHash(const std::string &torrent_file_path);

    static jsonWithSize
    getTorrentFileContents(const std::string &torrent_file_path);

    static std::vector<IPPort> getPeers(const std::string &info_hash,
                                        const std::string &tracker_url,
                                        const int left);
    static std::vector<IPPort> getPeers(const json &decoded_value);

    static std::string getHandshakeBuffer(const std::string &info_hash,
                                          bool support_extension);
    static std::pair<std::string, bool>
    doHandshakeHelper(const std::string &info_hash,
                      const TCPHandler &tcp_handler, bool support_extension);

    static bool verifyPeice(const std::string &piece,
                            const std::string &piece_hash);

    static std::unordered_map<std::string, std::string>
    parseMagnetLink(const std::string &magnet_link);

    static std::pair<std::vector<IPPort>, std::string>
    getTCPHandlerAndInfoHash(const std::string &magnet_link);

    static json doExtendedHandshake(const TCPHandler &tcp_handler);

    static std::pair<std::string, std::string>
    doMagentHandshake(const TCPHandler &tcp_handler,
                      const std::string info_hash);

    static json getMagnentLinkInfo(const TCPHandler &tcp_handler,
                                   const std::string info_hash);

    static void downloadPieceHelper(const std::string &output_file_path,
                                    const std::vector<IPPort> &peers,
                                    const std::string &info_hash,
                                    const json &info);
};

void dispatchCommand(int argc, char *argv[]);
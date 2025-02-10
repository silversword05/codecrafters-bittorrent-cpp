#pragma once

#include "Decoder.h"
#include "Encoder.h"
#include "TCPHandler.h"
#include <bits/stdc++.h>

enum class MessageType : uint8_t {
    CHOKE = 0,
    UNCHOKE = 1,
    INTERESTED = 2,
    NOT_INTERESTED = 3,
    HAVE = 4,
    BITFIELD = 5,
    REQUEST = 6,
    PIECE = 7,
    CANCEL = 8,
    HANDSHAKE = 9,
    BT_EXTENDED = 20,
};

struct Message {
    uint32_t length;
    MessageType type;
    std::string payload;

    static Message parseFromBuffer(const std::string &buffer);
    static std::string getInterestedMessage();
    static bool isUnchokeMessage(const std::string &buffer);
    static std::string getRequestMessage(uint32_t peice_index, uint32_t offset,
                                         uint32_t block_length);
    static std::string getExtenedHandshakeMessage();

    std::string serialize(bool convert_length_order = true) const;
    std::vector<bool> interpretAsBitfieldMessage() const;
    std::pair<uint32_t, std::string>
    interpretAsPieceMessage(const uint32_t peice_index) const;
};

struct PieceDownloader {
    PieceDownloader() = default;
    PieceDownloader(json decoded_value,
                    std::unique_ptr<TCPHandler> tcp_handler);
    std::string downloadPiece(const uint32_t piece_index);

  private:
    constexpr static size_t BLOCK_SIZE = 1 << (10 + 4); // 4kB

    std::unique_ptr<TCPHandler> tcp_handler;
    size_t standard_piece_length;
    size_t total_file_size;
    size_t num_pieces;
};
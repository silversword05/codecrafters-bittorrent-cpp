#include "PieceMessages.h"
#include <arpa/inet.h>

Message Message::parseFromBuffer(const std::string &buffer) {
    Message message;
    message.length = ntohl(*reinterpret_cast<const uint32_t *>(buffer.data()));
    message.type = static_cast<MessageType>(buffer[4]);
    message.payload = buffer.substr(5);
    return message;
}

std::string Message::serialize(bool convert_length_order) const {
    std::string res;
    res.resize(5 + payload.size());

    if (convert_length_order) {
        uint32_t length = htonl(this->length);
        *reinterpret_cast<uint32_t *>(res.data()) = length;
    } else {
        *reinterpret_cast<uint32_t *>(res.data()) = this->length;
    }
    res[4] = static_cast<uint8_t>(type);
    std::copy(payload.begin(), payload.end(), res.begin() + 5);
    return res;
}

std::vector<bool> Message::interpretAsBitfieldMessage() const {
    assert(("message type is not Bitfield", type == MessageType::BITFIELD));
    std::vector<bool> res;
    for (const char &byte : payload) {
        for (int i = 7; i >= 0; i--) {
            res.push_back(byte & (1 << i));
        }
    }
    return res;
}

std::pair<uint32_t, std::string>
Message::interpretAsPieceMessage(const uint32_t peice_index) const {
    assert(("message type is not Piece", type == MessageType::PIECE));
    uint32_t extracted_piece_index =
        ntohl(*reinterpret_cast<const uint32_t *>(payload.data()));
    assert(("Piece index mismatch", extracted_piece_index == peice_index));
    uint32_t offset =
        ntohl(*reinterpret_cast<const uint32_t *>(payload.data() + 4));
    return {offset, payload.substr(8)};
}

std::string Message::getInterestedMessage() {
    Message message;
    message.length = htonl(1);
    message.type = MessageType::INTERESTED;
    return message.serialize();
}

std::string Message::getRequestMessage(uint32_t piece_index, uint32_t offset,
                                       uint32_t block_length) {
    Message message;
    message.length = htonl(13);
    message.type = MessageType::REQUEST;
    message.payload.resize(12);
    *reinterpret_cast<uint32_t *>(message.payload.data()) = htonl(piece_index);
    *reinterpret_cast<uint32_t *>(message.payload.data() + 4) = htonl(offset);
    *reinterpret_cast<uint32_t *>(message.payload.data() + 8) =
        htonl(block_length);
    return message.serialize();
}

bool Message::isUnchokeMessage(const std::string &buffer) {
    Message message = parseFromBuffer(buffer);
    return message.type == MessageType::UNCHOKE;
}

std::string Message::getExtendedMessage(const ExtensionMessageType message_id,
                                        const json &payload) {
    Message message;
    message.type = MessageType::BT_EXTENDED;
    message.payload.push_back(static_cast<char>(message_id));
    message.payload += encodeDictionary(payload);
    message.length = htonl(message.payload.size() + 1);
    return message.serialize(false);
}

std::string Message::getExtenedHandshakeMessage() {
    json handshake_payload;
    handshake_payload["m"]["ut_metadata"] = 1;

    return Message::getExtendedMessage(ExtensionMessageType::EXTENDED_HANDSHAKE,
                                       handshake_payload);
}

std::string Message::getExtendedRequestMessage(const uint32_t piece_index) {
    json request_payload;
    request_payload["msg_type"] = 0;
    request_payload["piece"] = piece_index;

    return Message::getExtendedMessage(ExtensionMessageType::EXTENDED_METADATA,
                                       request_payload);
}

PieceDownloader::PieceDownloader(json info,
                                 std::unique_ptr<TCPHandler> tcp_handler)
    : tcp_handler(std::move(tcp_handler)) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;
    // std::cerr << info.dump(-1, ' ', false,
    // json::error_handler_t::replace) << std::endl;

    standard_piece_length = info["piece length"].get<size_t>();
    total_file_size = info["length"].get<size_t>();
    num_pieces =
        (total_file_size + standard_piece_length - 1) / standard_piece_length;
}

std::string PieceDownloader::downloadPiece(const uint32_t piece_index) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;
    // std::cerr << "Piece index: " << piece_index << std::endl;

    // Calculate the piece length (handling last piece separately)
    size_t piece_length = (piece_index == num_pieces - 1)
                              ? (total_file_size % standard_piece_length)
                              : standard_piece_length;
    if (piece_length == 0) {
        // This is the last piece and file size is a multiple of piece length
        piece_length = standard_piece_length;
    }

    std::string peice_data;

    // Remaining data to download for the current piece
    size_t remaining = piece_length;
    while (remaining > 0) {
        size_t block_length = std::min(BLOCK_SIZE, remaining);

        std::string request_message = Message::getRequestMessage(
            piece_index, piece_length - remaining, block_length);
        tcp_handler->sendData(request_message);
        std::string response = tcp_handler->readMessage();
        Message parsed_message = Message::parseFromBuffer(response);
        auto [offset, data] =
            parsed_message.interpretAsPieceMessage(piece_index);

        assert(("Block length mismatch", data.size() == block_length));
        assert(("Offset mismatch", offset == piece_length - remaining));
        peice_data += data;
        remaining -= block_length;
    }

    return peice_data;
}
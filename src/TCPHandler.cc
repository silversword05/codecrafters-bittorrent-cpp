#include "TCPHandler.h"
#include <arpa/inet.h>

TCPHandler::TCPHandler(const IPPort &peer) {
    struct sockaddr_in serv_addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
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
}

void TCPHandler::clearReadBuffer() const {
    char buffer[1024];
    ssize_t bytes_read;

    // Continuously read from the socket until there is no more data to read
    while ((bytes_read = recv(sock, buffer, sizeof(buffer), MSG_DONTWAIT)) >
           0) {
        std::cerr << "Discarding " << bytes_read << " bytes of read buffer"
                  << std::endl;
    }

    // Check for errors other than EWOULDBLOCK/EAGAIN
    if (bytes_read < 0 && errno != EWOULDBLOCK && errno != EAGAIN) {
        perror("Error clearing read buffer");
        throw std::runtime_error("Failed to clear read buffer: ");
    }
}

void TCPHandler::sendData(const std::string &data) const {
    clearReadBuffer();
    hexdump(data, "Sending data");
    if (send(sock, data.c_str(), data.size(), 0) < 0) {
        perror("send failed: ");
        throw std::runtime_error("Failed to send data: ");
    }
}

std::string TCPHandler::readHandShake() const {
    char buffer[HANDSHAKE_SIZE] = {0};
    int valread = read(sock, buffer, HANDSHAKE_SIZE);
    if (valread < HANDSHAKE_SIZE) {
        perror("read failed: ");
        throw std::runtime_error("Failed to read from socket: ");
    }
    std::string res = std::string(buffer, valread);
    hexdump(res, "Handshake read");
    return res;
}

std::string TCPHandler::readMessage() const {
    std::string message;
    message.resize(MESSAGE_LENGTH_SIZE);
    int read_len = read(sock, message.data(), MESSAGE_LENGTH_SIZE);
    if (read_len < 0) {
        perror("read failed: ");
        throw std::runtime_error("Failed to read from socket: ");
    }
    assert(("Failed to read message length", read_len == MESSAGE_LENGTH_SIZE));

    uint32_t message_length =
        ntohl(*reinterpret_cast<uint32_t *>(message.data()));
    std::cerr << "Message length: " << message_length << std::endl;
    assert(("Invalid message length",
            message_length > 0 && message_length <= (1 << 14) + 10));
    message.resize(message_length + MESSAGE_LENGTH_SIZE);

    int total_bytes_received = 0;
    while (total_bytes_received < message_length) {
        int bytes_received = read(
            sock, message.data() + MESSAGE_LENGTH_SIZE + total_bytes_received,
            message_length - total_bytes_received);
        if (bytes_received < 0) {
            perror("read failed: ");
            throw std::runtime_error("Failed to read from socket: ");
        }
        total_bytes_received += bytes_received;
    }
    assert(("Failed to read entire message",
            total_bytes_received == message_length));

    // hexdump(message, "Message read");
    return message;
}

void TCPHandler::hexdump(const std::string &str, std::string_view label) const {
    std::ios state(nullptr);
    state.copyfmt(std::cerr);

    std::cerr << label << " (" << str.size() << " bytes):" << std::endl;
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

TCPHandler::~TCPHandler() { close(sock); }
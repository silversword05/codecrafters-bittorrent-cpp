#pragma once
#include <bits/stdc++.h>

constexpr size_t HANDSHAKE_SIZE = 68;
constexpr size_t MESSAGE_LENGTH_SIZE = 4;

using IPPort = std::pair<std::string, uint16_t>;
struct TCPHandler {
    explicit TCPHandler(const IPPort &peer);
    TCPHandler(const TCPHandler &other) = delete;
    TCPHandler(TCPHandler &&other) noexcept = default;

    void sendData(const std::string &data) const;
    void clearReadBuffer() const;
    std::string readHandShake() const;
    std::string readMessage() const;

    ~TCPHandler();

  private:
    void hexdump(const std::string &str, std::string_view label) const;
    int sock;
};
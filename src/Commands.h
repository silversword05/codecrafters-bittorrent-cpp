#pragma once

#include "Encoder.h"
#include "Decoder.h"

void decodeTorrentFile(const std::string &file_path);
bool dispatchCommand(int argc, char *argv[]);
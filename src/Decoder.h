#include <bits/stdc++.h>

#include "lib/nlohmann/json.hpp"
using json = nlohmann::json;
using jsonWithSize = std::pair<json, size_t>;

jsonWithSize decodeString(const std::string_view encoded_value);
jsonWithSize decodeIntegers(const std::string_view encoded_value);
jsonWithSize decodeList(const std::string_view encoded_value);
jsonWithSize decodeDictionary(const std::string_view encoded_value);
jsonWithSize decodeBencodedValue(const std::string_view encoded_value);
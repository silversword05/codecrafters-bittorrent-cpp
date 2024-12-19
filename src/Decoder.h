#include <bits/stdc++.h>

#include "lib/nlohmann/json.hpp"
using json = nlohmann::json;

json stringDecoding(const std::string& encoded_value);
json decodeIntegers(const std::string& encoded_value);
json decodeBencodedValue(const std::string& encoded_value);
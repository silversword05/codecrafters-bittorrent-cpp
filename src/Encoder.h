#pragma once
#include <bits/stdc++.h>

#include "lib/sha1.hpp"
#include "lib/nlohmann/json.hpp"
using json = nlohmann::json;

std::string encodeString(const std::string &str);
template <std::integral IntT> std::string encodeInteger(const IntT &number);
std::string encodeList(const json &list);
std::string encodeDictionary(const json &dict);
std::string encodeJson(json value);

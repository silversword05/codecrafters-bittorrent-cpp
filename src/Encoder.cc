#include "Encoder.h"

std::string encodeString(const std::string &str) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;
    return std::to_string(str.size()) + ':' + str;
}

template <std::integral IntT> std::string encodeInteger(const IntT &number) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;
    return 'i' + std::to_string(number) + 'e';
}

std::string encodeList(const json &list) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;
    std::string res = "l";
    for (const auto &val : list) {
        res += encodeJson(val);
    }
    return res + "e";
}

std::string encodeDictionary(const json &dict) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;
    std::string res = "d";
    for (auto &[key, val] : dict.items()) {
        res = res + encodeString(key);
        res = res + encodeJson(val);
    }
    return res + "e";
}

std::string encodeJson(json value) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;

    std::string res = "";

    if (value.is_string()) {
        res = res + encodeString(value.get<std::string>());
    } else if (value.is_number_integer()) {
        res = res + encodeInteger(value.get<int>());
    } else if (value.is_array()) {
        res = res + encodeList(value);
    } else if (value.is_object()) {
        res = res + encodeDictionary(value);
    } else {
        throw std::runtime_error("Invalid JSON value");
    }

    return res;
}
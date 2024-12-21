#include "Decoder.h"

jsonWithSize stringDecoding(const std::string_view encoded_value) {
    // Example: "5:hello" -> "hello"
    size_t colon_index = encoded_value.find(':');
    if (colon_index != std::string::npos) {
        std::string_view number_string = encoded_value.substr(0, colon_index);
        int64_t number = std::stoi(std::string(number_string));
        std::string_view str = encoded_value.substr(colon_index + 1, number);
        return {json(str), 1 + colon_index + number};
    } else {
        throw std::runtime_error("Invalid encoded value: " +
                                 std::string(encoded_value));
    }
}

jsonWithSize decodeIntegers(const std::string_view encoded_value) {
    // Example: "i42e" -> 42
    std::string_view number_string =
        encoded_value.substr(1, encoded_value.find('e') - 1);
    if (number_string.empty()) {
        throw std::runtime_error("Invalid encoded value: " +
                                 std::string(encoded_value));
    }
    int64_t number = std::stoll(std::string(number_string));
    return {json(number), encoded_value.find('e') + 1};
}

jsonWithSize decodeList(const std::string_view encoded_value) {
    // Example: "l5:hello5:worlde" -> ["hello", "world"]
    assert(("The provided size is too small", encoded_value.size() >= 2));
    json res = json::array();
    size_t i = 1;
    while (i < encoded_value.size() - 1 && encoded_value[i] != 'e') {
        auto [val, size_consumed] =
            decodeBencodedValue(encoded_value.substr(i));
        res.push_back(val);
        i += size_consumed;
    }
    assert(("The list is not properly terminated", encoded_value[i] == 'e'));
    return {res, i + 1};
}

jsonWithSize decodeBencodedValue(const std::string_view encoded_value) {
    if (std::isdigit(encoded_value[0])) {
        return stringDecoding(encoded_value);
    } else if (encoded_value[0] == 'i') {
        return decodeIntegers(encoded_value);
    } else if (encoded_value[0] == 'l') {
        return decodeList(encoded_value);
    } else {
        throw std::runtime_error("Invalid encoded value: " +
                                 std::string(encoded_value));
    }
}
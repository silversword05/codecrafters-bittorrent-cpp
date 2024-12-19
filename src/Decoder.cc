#include "Decoder.h"

json stringDecoding(const std::string &encoded_value) {
    // Example: "5:hello" -> "hello"
    size_t colon_index = encoded_value.find(':');
    if (colon_index != std::string::npos) {
        std::string number_string = encoded_value.substr(0, colon_index);
        int64_t number = std::atoll(number_string.c_str());
        std::string str = encoded_value.substr(colon_index + 1, number);
        return json(str);
    } else {
        throw std::runtime_error("Invalid encoded value: " + encoded_value);
    }
}

json decodeIntegers(const std::string &encoded_value) {
    // Example: "i42e" -> 42
    std::string number_string =
        encoded_value.substr(1, encoded_value.size() - 2);
    int64_t number = std::atoll(number_string.c_str());
    return json(number);
}

json decodeBencodedValue(const std::string &encoded_value) {
    if (std::isdigit(encoded_value[0])) {
        return stringDecoding(encoded_value);
    } else if (encoded_value[0] == 'i' &&
               encoded_value[encoded_value.size() - 1] == 'e') {
        return decodeIntegers(encoded_value);
    } else {
        throw std::runtime_error("Unhandled encoded value: " + encoded_value);
    }
}
#include "Decoder.h"

jsonWithSize decodeString(const std::string_view encoded_value) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;

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
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;

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
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;

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

jsonWithSize decodeDictionary(const std::string_view encoded_value) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;

    // Example: "d3:cow3:moo4:spam4:eggse" -> {"cow": "moo", "spam": "eggs"}
    assert(("The provided size is too small", encoded_value.size() >= 2));
    json res = json::object();
    size_t i = 1;
    while (i < encoded_value.size() - 1 && encoded_value[i] != 'e') {
        // std::cerr << "Debug strings " << encoded_value.substr(i) <<
        // std::endl;
        auto [key, key_size] = decodeBencodedValue(encoded_value.substr(i));
        i += key_size;
        auto [val, val_size] = decodeBencodedValue(encoded_value.substr(i));
        res[key.get<std::string>()] = val;
        i += val_size;
    }
    assert(
        ("The dictionary is not properly terminated", encoded_value[i] == 'e'));
    return {res, i + 1};
}

jsonWithSize decodeBencodedValue(const std::string_view encoded_value) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;

    if (std::isdigit(encoded_value[0])) {
        return decodeString(encoded_value);
    } else if (encoded_value[0] == 'i') {
        return decodeIntegers(encoded_value);
    } else if (encoded_value[0] == 'l') {
        return decodeList(encoded_value);
    } else if (encoded_value[0] == 'd') {
        return decodeDictionary(encoded_value);
    } else {
        throw std::runtime_error("Invalid encoded value: " +
                                 std::string(encoded_value));
    }
}
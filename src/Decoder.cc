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

void decodeTorrentFile(const std::string &file_path) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;

    std::ifstream file(file_path);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + file_path);
    }

    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    auto [decoded_value, sizeConsumed] = decodeBencodedValue(content);
    assert(("Entire string not consumed", sizeConsumed == content.size()));
    std::cout << "Tracker URL: " << decoded_value["announce"].get<std::string>()
              << std::endl;
    std::cout << "Length: " << decoded_value["info"]["length"].get<int>()
              << std::endl;
}

bool dispatchCommand(int argc, char *argv[]) {
    // std::cerr << __PRETTY_FUNCTION__ << std::endl;

    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " decode <encoded_value>"
                  << std::endl;
        return false;
    }

    std::string command = argv[1];

    if (command == "decode") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " decode <encoded_value>"
                      << std::endl;
            return false;
        }
        std::string encoded_value = argv[2];
        auto [decoded_value, size_consumed] =
            decodeBencodedValue(encoded_value);
        assert(("Entire string not consumed",
                size_consumed == encoded_value.size()));
        std::cout << decoded_value.dump() << std::endl;
    } else if (command == "info") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " info <file_path>"
                      << std::endl;
            return false;
        }
        std::string file_path = argv[2];
        decodeTorrentFile(file_path);
    } else {
        std::cerr << "unknown command: " << command << std::endl;
        return false;
    }
    return true;
}
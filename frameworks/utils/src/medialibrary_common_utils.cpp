/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "medialibrary_common_utils.h"

#include <regex>
#include "medialibrary_errno.h"
#include "medialibrary_napi_utils.h"
#include "openssl/sha.h"

namespace OHOS {
namespace Media {
const std::string MediaLibraryCommonUtils::CHAR2HEX_TABLE[UCHAR_MAX + 1] = {
    "00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0A", "0B", "0C", "0D", "0E", "0F",
    "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1A", "1B", "1C", "1D", "1E", "1F",
    "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2A", "2B", "2C", "2D", "2E", "2F",
    "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3A", "3B", "3C", "3D", "3E", "3F",

    "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "4A", "4B", "4C", "4D", "4E", "4F",
    "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "5A", "5B", "5C", "5D", "5E", "5F",
    "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6A", "6B", "6C", "6D", "6E", "6F",
    "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "7A", "7B", "7C", "7D", "7E", "7F",

    "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "8A", "8B", "8C", "8D", "8E", "8F",
    "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "9A", "9B", "9C", "9D", "9E", "9F",
    "A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "AA", "AB", "AC", "AD", "AE", "AF",
    "B0", "B1", "B2", "B3", "B4", "B5", "B6", "B7", "B8", "B9", "BA", "BB", "BC", "BD", "BE", "BF",

    "C0", "C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "CA", "CB", "CC", "CD", "CE", "CF",
    "D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "DA", "DB", "DC", "DD", "DE", "DF",
    "E0", "E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8", "E9", "EA", "EB", "EC", "ED", "EE", "EF",
    "F0", "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "FA", "FB", "FC", "FD", "FE", "FF"
};

void MediaLibraryCommonUtils::Char2Hex(const unsigned char *data, const size_t len, std::string &hexStr)
{
    constexpr int CHAR_WIDTH = 8;
    constexpr int HEX_WIDTH = 4;
    constexpr size_t OUT_HEXSTR_SIZE = SHA256_DIGEST_LENGTH * (CHAR_WIDTH / HEX_WIDTH);
    hexStr = "";
    hexStr.reserve(OUT_HEXSTR_SIZE);
    for (size_t i = 0; i < len; i++) {
        hexStr.append(CHAR2HEX_TABLE[data[i]]);
    }
}

int32_t MediaLibraryCommonUtils::GenKey(const unsigned char *data, const size_t len, std::string &key)
{
    if (len == 0 || len > HASH_INPUT_MAX_LENGTH) {
        return -EINVAL;
    }

    unsigned char hash[SHA256_DIGEST_LENGTH] = "";
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(hash, &ctx);

    /* here we translate sha256 hash to hexadecimal. each 8-bit char will be presented by two characters([0-9a-f]) */
    Char2Hex(hash, SHA256_DIGEST_LENGTH, key);
    return E_OK;
}

int32_t MediaLibraryCommonUtils::GenKeySHA256(const std::vector<uint8_t> &input, std::string &key)
{
    return GenKey(input.data(), input.size(), key);
}

int32_t MediaLibraryCommonUtils::GenKeySHA256(const std::string &input, std::string &key)
{
    return GenKey((const unsigned char *)input.c_str(), input.size(), key);
}

void MediaLibraryCommonUtils::Trim(std::string &str)
{
    if (!str.empty()) {
        str.erase(0, str.find_first_not_of(" "));
        str.erase(str.find_last_not_of(" ") + 1);
    }
}

bool MediaLibraryCommonUtils::CheckWhiteList(const std::string &express)
{
    std::string exp = express;
    Trim(exp);
    auto pos = exp.find_last_of(" ");
    if (pos != std::string::npos) {
        exp = exp.substr(pos + 1, exp.length());
    }

    for (auto key : fileKeyEnumValues) {
        if (key == exp) {
            return true;
        }
    }

    return false;
}

bool MediaLibraryCommonUtils::CheckExpressValidation(std::vector<std::string> &sepratedStr)
{
    for (auto str : sepratedStr) {
        if (!CheckWhiteList(str)) {
        }
    }

    return true;
}

void MediaLibraryCommonUtils::SeprateSelection(const std::string &strCondition, std::vector<std::string> &sepratedStr)
{
    // seprate strCondition by where Operator
    std::regex pattern("\\s*<=\\s*|\\s*>=\\s*|\\s*<>\\s*|\\s*=\\s*|\\s*>\\s*|" \
                            "\\s*<\\s*|\\s*BETWEEN\\s*|\\s*LIKE\\s*|\\s*IN\\s*",
                    std::regex_constants::ECMAScript | std::regex_constants::icase);
    std::sregex_token_iterator iter(strCondition.begin(), strCondition.end(), pattern, -1);
    decltype(iter) end;
    for (; iter != end; iter++) {
        sepratedStr.push_back(iter->str());
    }
}

bool MediaLibraryCommonUtils::CheckKeyWord(const std::string &strCondition)
{
    std::regex pattern("\\s*exec\\s*|\\s*insert\\s*|\\s*delete\\s*|\\s*update\\s*|" \
                            "\\s*join\\s*|\\s*union\\s*|\\s*master\\s*|\\s*truncate\\s*",
                    std::regex_constants::ECMAScript | std::regex_constants::icase);

    if (regex_search(strCondition, pattern)) {
        return false;
    }

    return true;
}

bool MediaLibraryCommonUtils::CheckIllegalCharacter(const std::string &strCondition)
{
    /* if strCondition contains ';', it will be sepreate to two clause */
    if (strCondition.find(';') == std::string::npos) {
        return true;
    }
    /* other check to do */
    return false;
}

bool MediaLibraryCommonUtils::CheckWhereClause(const std::string &whereClause)
{
    /* check whether query condition has illegal character */
    if (!CheckIllegalCharacter(whereClause)) {
        return false;
    }

    /* check whether query condition has key word */
    if (!CheckKeyWord(whereClause)) {
        return false;
    }

    std::vector<std::string> sepratedStr;
    SeprateSelection(whereClause, sepratedStr);
    /* check every query condition */
    return CheckExpressValidation(sepratedStr);
}

void MediaLibraryCommonUtils::AppendSelections(std::string &selections)
{
    if (selections.empty()) {
        return;
    }
    selections = "(" + selections + ")";
}
} // namespace Media
} // namespace OHOS

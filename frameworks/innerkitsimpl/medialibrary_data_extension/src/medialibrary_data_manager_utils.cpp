/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "medialibrary_data_manager_utils.h"
#include <regex>
#include "openssl/sha.h"
#include "media_log.h"
#include "media_file_utils.h"

using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::RdbDataShareAdapter;

namespace OHOS {
namespace Media {
string MediaLibraryDataManagerUtils::GetFileName(const string &path)
{
    string name;
    size_t slashIndex = path.rfind("/");
    if (slashIndex != string::npos) {
        name = path.substr(slashIndex + 1);
    }
    return name;
}

string MediaLibraryDataManagerUtils::GetParentPath(const string &path)
{
    string name;
    size_t slashIndex = path.rfind("/");
    if (slashIndex != string::npos) {
        name = path.substr(0, slashIndex);
    }

    return name;
}

bool MediaLibraryDataManagerUtils::IsNumber(const string &str)
{
    if (str.empty()) {
        MEDIA_ERR_LOG("IsNumber input is empty ");
        return false;
    }

    for (char const &c : str) {
        if (isdigit(c) == 0) {
            MEDIA_ERR_LOG("Index is not a number");
            return false;
        }
    }
    return true;
}

std::string MediaLibraryDataManagerUtils::GetFileTitle(const std::string& displayName)
{
    std::string title = "";
    if (!displayName.empty()) {
        std::string::size_type pos = displayName.find_first_of('.');
        if (pos == displayName.length()) {
            return displayName;
        }
        title = displayName.substr(0, pos);
        MEDIA_DEBUG_LOG("title substr = %{private}s", title.c_str());
    }
    return title;
}

string MediaLibraryDataManagerUtils::GetOperationType(const string &uri)
{
    string oprn("");
    size_t found = uri.rfind('/');
    if (found != string::npos) {
        oprn = uri.substr(found + 1);
    }

    return oprn;
}

string MediaLibraryDataManagerUtils::GetIdFromUri(const string &uri)
{
    string rowNum = "-1";

    size_t pos = uri.rfind('/');
    if (pos != std::string::npos) {
        rowNum = uri.substr(pos + 1);
    }

    return rowNum;
}

string MediaLibraryDataManagerUtils::GetNetworkIdFromUri(const string &uri)
{
    string deviceId;
    if (uri.empty()) {
        return deviceId;
    }
    size_t pos = uri.find(MEDIALIBRARY_DATA_ABILITY_PREFIX);
    if (pos == string::npos) {
        return deviceId;
    }

    string tempUri = uri.substr(MEDIALIBRARY_DATA_ABILITY_PREFIX.length());
    if (tempUri.empty()) {
        return deviceId;
    }
    MEDIA_INFO_LOG("MediaLibraryDataManagerUtils::GetNetworkIdFromUri tempUri = %{private}s", tempUri.c_str());
    pos = tempUri.find_first_of('/');
    if (pos == 0 || pos == string::npos) {
        return deviceId;
    }
    deviceId = tempUri.substr(0, pos);

    return deviceId;
}

int32_t MediaLibraryDataManagerUtils::MakeHashDispalyName(const std::string &input, std::string &outRes)
{
    vector<uint8_t> data(input.begin(), input.end());
    MEDIA_INFO_LOG("MakeHashDispalyName IN");
    if (data.size() <= 0) {
        MEDIA_ERR_LOG("Empty data");
        return DATA_ABILITY_GET_HASH_FAIL;
    }
    unsigned char hash[SHA256_DIGEST_LENGTH] = "";
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data.data(), data.size());
    SHA256_Final(hash, &ctx);
    // here we translate sha256 hash to hexadecimal. each 8-bit char will be presented by two characters([0-9a-f])
    constexpr int CHAR_WIDTH = 8;
    constexpr int HEX_WIDTH = 4;
    constexpr unsigned char HEX_MASK = 0xf;
    constexpr int HEX_A = 10;
    outRes.reserve(SHA256_DIGEST_LENGTH * (CHAR_WIDTH / HEX_WIDTH));
    for (unsigned char i : hash) {
        unsigned char hex = i >> HEX_WIDTH;
        if (hex < HEX_A) {
            outRes.push_back('0' + hex);
        } else {
            outRes.push_back('a' + hex - HEX_A);
        }
        hex = i & HEX_MASK;
        if (hex < HEX_A) {
            outRes.push_back('0' + hex);
        } else {
            outRes.push_back('a' + hex - HEX_A);
        }
    }
    MEDIA_DEBUG_LOG("MakeHashDispalyName OUT [%{private}s]", outRes.c_str());
    return DATA_ABILITY_SUCCESS;
}

string MediaLibraryDataManagerUtils::GetDisPlayNameFromPath(std::string &path)
{
    string displayName;
    size_t lastSlashPosition = path.rfind("/");
    if (lastSlashPosition != string::npos) {
        displayName = path.substr(lastSlashPosition + 1);
    }
    return displayName;
}

bool MediaLibraryDataManagerUtils::CheckOpenMode(const string &mode)
{
    MEDIA_INFO_LOG("checkOpenMode in mode %{private}s", mode.c_str());

    string lowModeStr = mode;
    transform(lowModeStr.begin(), lowModeStr.end(), lowModeStr.begin(), [](unsigned char c) {
        return tolower(c);
    });

    size_t wIndex = lowModeStr.rfind('w');
    if (wIndex != string::npos) {
        return true;
    }
    return false;
}

bool MediaLibraryDataManagerUtils::CheckFilePending(const shared_ptr<FileAsset> fileAsset)
{
    MEDIA_INFO_LOG("checkFilePending in");
    if (fileAsset->IsPending()) {
        MEDIA_INFO_LOG("checkFilePending IsPending true");
        return true;
    } else if (fileAsset->GetTimePending() > 0 &&
        (MediaFileUtils::UTCTimeSeconds() - fileAsset->GetTimePending()) > TIMEPENDING_MIN) {
        MEDIA_INFO_LOG("checkFilePending IsPending true");
        return true;
    }
    MEDIA_INFO_LOG("checkFilePending IsPending false");
    return false;
}

void MediaLibraryDataManagerUtils::SplitKeyValue(const string& keyValue, string &key, string &value)
{
    string::size_type pos = keyValue.find('=');
    if (string::npos != pos) {
        key = keyValue.substr(0, pos);
        value = keyValue.substr(pos + 1);
    }
}

void MediaLibraryDataManagerUtils::SplitKeys(const string& query, vector<string>& keys)
{
    string::size_type pos1 = 0;
    string::size_type pos2 = query.find('&');
    while (string::npos != pos2) {
        keys.push_back(query.substr(pos1, pos2-pos1));
        pos1 = pos2 + 1;
        pos2 = query.find('&', pos1);
    }
    if (pos1 != query.length()) {
        keys.push_back(query.substr(pos1));
    }
}

string MediaLibraryDataManagerUtils::ObtionCondition(string &strQueryCondition, const vector<string> &whereArgs)
{
    for (string args : whereArgs) {
        size_t pos = strQueryCondition.find('?');
        if (pos != string::npos) {
            strQueryCondition.replace(pos, 1, "'" + args + "'");
        }
    }
    return strQueryCondition;
}

} // namespace Media
} // namespace OHOS

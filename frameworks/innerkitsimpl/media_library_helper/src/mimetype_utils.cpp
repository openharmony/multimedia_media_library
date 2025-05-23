/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "mimetype_utils.h"

#include <algorithm>
#include <fstream>

#include "media_log.h"
#include "medialibrary_errno.h"

using std::string;
using std::vector;
using std::unordered_map;
using namespace nlohmann;

namespace OHOS {
namespace Media {
using MimeTypeMap = unordered_map<string, vector<string>>;

MimeTypeMap MimeTypeUtils::mediaJsonMap_;
const string MIMETYPE_JSON_PATH = "/system/etc/userfilemanager/userfilemanager_mimetypes.json";
const string DEFAULT_MIME_TYPE = "application/octet-stream";

/**
 * The format of the target json file:
 * First floor: Media type string, such as image, video, audio, etc.
 * Second floor: Mime type string
 * Third floor: Extension array.
*/
void MimeTypeUtils::CreateMapFromJson()
{
    std::ifstream jFile(MIMETYPE_JSON_PATH);
    if (!jFile.is_open()) {
        MEDIA_ERR_LOG("Failed to open: %{private}s", MIMETYPE_JSON_PATH.c_str());
        return;
    }
    json firstFloorObjs;
    jFile >> firstFloorObjs;
    jFile.close();
    for (auto& firstFloorObj : firstFloorObjs.items()) {
        json secondFloorJsons = json::parse(firstFloorObj.value().dump(), nullptr, false);
        if (secondFloorJsons.is_discarded() || secondFloorJsons.empty()) {
            MEDIA_ERR_LOG("parse secondFloorJsons failed");
            return;
        }
        for (auto& secondFloorJson : secondFloorJsons.items()) {
            json thirdFloorJsons = json::parse(secondFloorJson.value().dump(), nullptr, false);
            if (thirdFloorJsons.is_discarded() || thirdFloorJsons.empty()) {
                MEDIA_ERR_LOG("parse thirdFloorJsons failed");
                return;
            }
            // Key: MimeType, Value: Extension array.
            mediaJsonMap_.insert(std::pair<string, vector<string>>(secondFloorJson.key(), thirdFloorJsons));
        }
    }
}

bool MimeTypeUtils::IsMimeTypeMapEmpty()
{
    return mediaJsonMap_.empty();
}

int32_t MimeTypeUtils::InitMimeTypeMap()
{
    CreateMapFromJson();
    if (mediaJsonMap_.empty()) {
        return E_FAIL;
    }
    return E_OK;
}

string MimeTypeUtils::GetMimeTypeFromExtension(const string &extension)
{
    return GetMimeTypeFromExtension(extension, mediaJsonMap_);
}

string MimeTypeUtils::GetMimeTypeFromExtension(const string &extension,
    const MimeTypeMap &mimeTypeMap)
{
    std::string tmp = std::move(extension);
    std::transform(tmp.begin(), tmp.end(), tmp.begin(), ::tolower);
    for (auto &item : mimeTypeMap) {
        for (auto &ext : item.second) {
            if (ext == tmp) {
                return item.first;
            }
        }
    }
    return DEFAULT_MIME_TYPE;
}

MediaType MimeTypeUtils::GetMediaTypeFromMimeType(const string &mimeType)
{
    size_t pos = mimeType.find_first_of("/");
    if (pos == string::npos) {
        MEDIA_ERR_LOG("Invalid mime type: %{private}s", mimeType.c_str());
        return MEDIA_TYPE_FILE;
    }
    string prefix = mimeType.substr(0, pos);
    if (prefix == "audio") {
        return MEDIA_TYPE_AUDIO;
    } else if (prefix == "video") {
        return MEDIA_TYPE_VIDEO;
    } else if (prefix == "image") {
        return MEDIA_TYPE_IMAGE;
    } else {
        return MEDIA_TYPE_FILE;
    }
}
}
}

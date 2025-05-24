/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#define MLOG_TAG "Media_Cloud_Utils"

#include "cloud_media_uri_utils.h"

#include "media_log.h"
#include "medialibrary_errno.h"
#include "string_ex.h"

namespace OHOS::Media::CloudSync {
std::string CloudMediaUriUtils::GetAnonyStringStrictly(const std::string &input)
{
    constexpr size_t INT32_MIN_ID_LENGTH = 17;
    constexpr size_t INT32_PLAINTEXT_LENGTH = 8;
    std::string anonyStr("********");

    size_t length = input.length();
    if (length < INT32_MIN_ID_LENGTH) {
        return anonyStr;
    } else {
        std::string result = input.substr(0, INT32_PLAINTEXT_LENGTH);
        result += anonyStr;
        result += input.substr(length - INT32_PLAINTEXT_LENGTH, INT32_PLAINTEXT_LENGTH);
        return result;
    }
}

int32_t CloudMediaUriUtils::GetFileIdFromUri(const std::string &uri, int32_t &fileUniqueId)
{
    static std::string mediaDirPath = "file://media/Photo/";
    size_t index = uri.find(mediaDirPath);
    if (index != 0) {
        MEDIA_INFO_LOG(
            "Failed to get media dir from uri: %{public}s", CloudMediaUriUtils::GetAnonyStringStrictly(uri).c_str());
        return E_INVAL_ARG;
    }
    std::string uriTails = uri.substr(index + mediaDirPath.length());
    index = uriTails.find('/');
    if (index == std::string::npos) {
        MEDIA_INFO_LOG(
            "Failed to get fileId from uri: %{public}s", CloudMediaUriUtils::GetAnonyStringStrictly(uri).c_str());
        return E_INVAL_ARG;
    }
    std::string fileId = uriTails.substr(0, index);
    if (!all_of(fileId.begin(), fileId.end(), ::isdigit)) {
        MEDIA_INFO_LOG("Invalid fileId from uri: %{public}s", fileId.c_str());
        return E_INVAL_ARG;
    }
    if (!StrToInt(fileId, fileUniqueId)) {
        MEDIA_INFO_LOG("Invalid meida uri: %{public}s", CloudMediaUriUtils::GetAnonyStringStrictly(uri).c_str());
        return E_INVAL_ARG;
    }
    return E_OK;
}

int32_t CloudMediaUriUtils::GetFileIds(const std::vector<std::string> &uris, std::vector<int32_t> &fileIds)
{
    fileIds.clear();
    for (auto &uri : uris) {
        int32_t fileId = 0;
        auto ret = CloudMediaUriUtils::GetFileIdFromUri(uri, fileId);
        CHECK_AND_CONTINUE_ERR_LOG(ret == E_OK, "Failed to get fileId from uri: %{public}s", uri.c_str());
        fileIds.push_back(fileId);
        MEDIA_INFO_LOG("GetFileIds uri:%{public}s, fileId:%{public}d", uri.c_str(), fileId);
    }
    return uris.size() == fileIds.size() ? E_OK : E_INVAL_ARG;
}
}  // namespace OHOS::Media::CloudSync
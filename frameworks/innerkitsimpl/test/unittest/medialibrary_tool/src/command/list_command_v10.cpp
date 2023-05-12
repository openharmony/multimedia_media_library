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
#include "command/list_command_v10.h"

#include <set>

#include "constant.h"
#include "medialibrary_errno.h"
#include "userfile_client_ex.h"
#include "utils/database_utils.h"

namespace OHOS {
namespace Media {
namespace MediaTool {
int32_t ListAssets(const ExecEnv &env, const MediaType mediaType, const std::string &uri)
{
    std::string tableName;
    if (mediaType != MediaType::MEDIA_TYPE_DEFAULT) {
        tableName = UserFileClientEx::GetTableNameByMediaType(mediaType);
    }
    if (tableName.empty() && (!uri.empty())) {
        tableName = UserFileClientEx::GetTableNameByUri(uri);
    }
    if (tableName.empty()) {
        printf("%s table name issue. mediaType:%d, uri:%s\n", STR_FAIL.c_str(), mediaType, uri.c_str());
        return Media::E_ERR;
    }
    printf("Table Name: %s\n", tableName.c_str());
    std::shared_ptr<FetchResult<FileAsset>> fetchResult;
    auto res = UserFileClientEx::Query(mediaType, uri, fetchResult);
    if (res != Media::E_OK) {
        printf("%s query issue failed. mediaType:%d, uri:%s\n", STR_FAIL.c_str(), mediaType, uri.c_str());
        return Media::E_ERR;
    }
    if (fetchResult == nullptr) {
        return Media::E_OK;
    }
    DatabaseUtils::Dump(env.dumpOpt, fetchResult);
    fetchResult->Close();
    return Media::E_OK;
}

int32_t ListCommandV10::Start(const ExecEnv &env)
{
    if (!env.uri.empty()) {
        return ListAssets(env, MediaType::MEDIA_TYPE_DEFAULT, env.uri);
    }
    std::set<std::string> tableNameSet;
    bool hasError = false;
    auto mediaTypes = UserFileClientEx::GetSupportTypes();
    for (auto mediaType : mediaTypes) {
        std::string tableName = UserFileClientEx::GetTableNameByMediaType(mediaType);
        auto res = tableNameSet.insert(tableName);
        if (!res.second) {
            continue;
        }
        if (ListAssets(env, mediaType, env.uri) != Media::E_OK) {
            hasError = true;
        }
        printf("\n");
    }
    return hasError ? Media::E_ERR : Media::E_OK;
}
} // namespace MediaTool
} // namespace Media
} // namespace OHOS

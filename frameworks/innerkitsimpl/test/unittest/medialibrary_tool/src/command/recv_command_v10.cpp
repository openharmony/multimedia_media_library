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
#include "command/recv_command_v10.h"

#include <fcntl.h>
#include <set>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "constant.h"
#include "directory_ex.h"
#include "media_file_utils.h"
#include "medialibrary_errno.h"
#include "userfile_client_ex.h"
#include "utils/file_utils.h"

namespace OHOS {
namespace Media {
namespace MediaTool {
constexpr mode_t OPEN_MODE = 0664;
bool GetFileName(const ExecEnv &env, const FileAsset &fileAsset, std::string &fileName)
{
    if (!env.uri.empty()) { // recv a file
        fileName = env.recvPath;
        return true;
    }
    // recv all file to directory
    const std::string &fileAssetPath = fileAsset.GetPath();
    if (fileAssetPath.find(ROOT_MEDIA_DIR) != 0) {
        printf("%s file path issue. fileName:%s\n", STR_FAIL.c_str(), fileAssetPath.c_str());
        return false;
    }
    std::string relativePath = fileAssetPath.substr(ROOT_MEDIA_DIR.length());
    std::string fileFullPath = env.recvPath + relativePath;
    std::string fileParentPath = ExtractFilePath(fileFullPath);
    ForceCreateDirectory(fileParentPath);
    fileName = fileFullPath;
    return true;
}

int32_t RecvFile(const ExecEnv &env, const FileAsset &fileAsset)
{
    std::string fileName;
    if (!GetFileName(env, fileAsset, fileName)) {
        return Media::E_ERR;
    }
    auto wfd = open(fileName.c_str(), O_CREAT | O_WRONLY | O_CLOEXEC, OPEN_MODE);
    if (wfd <= 0) {
        printf("%s open file failed. errno:%d, fileName:%s\n", STR_FAIL.c_str(), errno, fileName.c_str());
        return Media::E_ERR;
    }
    auto rfd = UserFileClientEx::Open(fileAsset.GetUri(), Media::MEDIA_FILEMODE_READONLY);
    if (rfd <= 0) {
        printf("%s open failed. uri:%s\n", STR_FAIL.c_str(), fileAsset.GetUri().c_str());
        close(wfd);
        return Media::E_ERR;
    }
    auto ret = FileUtils::SendData(rfd, wfd);
    if (!ret) {
        printf("%s receive data failed. uri:%s\n", STR_FAIL.c_str(), fileAsset.GetUri().c_str());
    } else {
        printf("%s\n", fileName.c_str());
    }
    UserFileClientEx::Close(fileAsset.GetUri(), rfd, Media::MEDIA_FILEMODE_READONLY);
    close(wfd);
    return ret ? Media::E_OK : Media::E_ERR;
}

int32_t RecvAssets(const ExecEnv &env, const MediaType mediaType, const std::string &uri)
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
        printf("%s query issue. mediaType:%d, uri:%s\n", STR_FAIL.c_str(), mediaType, uri.c_str());
        return Media::E_ERR;
    }
    if (fetchResult == nullptr) {
        return Media::E_OK;
    }
    auto count = fetchResult->GetCount();
    for (int32_t index = 0; index < count; index++) {
        auto fileAsset = fetchResult->GetObjectAtPosition(index);
        RecvFile(env, *fileAsset);
    }
    fetchResult->Close();
    return Media::E_OK;
}

int32_t RecvCommandV10::Start(const ExecEnv &env)
{
    if (!env.uri.empty()) {
        return RecvAssets(env, MediaType::MEDIA_TYPE_DEFAULT, env.uri);
    }
    std::set<std::string> tableNameSet;
    bool hasError = false;
    auto mediaTypes = GetSupportTypes();
    for (auto mediaType : mediaTypes) {
        std::string tableName = UserFileClientEx::GetTableNameByMediaType(mediaType);
        auto res = tableNameSet.insert(tableName);
        if (!res.second) {
            continue;
        }
        if (RecvAssets(env, mediaType, env.uri) != Media::E_OK) {
            hasError = true;
        }
        printf("\n");
    }
    return hasError ? Media::E_ERR : Media::E_OK;
}
} // namespace MediaTool
} // namespace Media
} // namespace OHOS

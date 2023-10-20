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

#include <cerrno>
#include <fcntl.h>
#include <set>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "constant.h"
#include "datashare_result_set.h"
#include "directory_ex.h"
#include "media_file_utils.h"
#include "medialibrary_errno.h"
#include "userfile_client_ex.h"

namespace OHOS {
namespace Media {
namespace MediaTool {
constexpr mode_t OPEN_MODE = 0664;
static bool GetWriteFilePath(const ExecEnv &env, const FileAsset &fileAsset, std::string &wFilePath)
{
    wFilePath = env.recvParam.recvPath;
    if (!MediaFileUtils::IsDirectory(wFilePath)) {
        if (env.recvParam.isRecvAll) {
            printf("RecvFilePath:%s is not a directory.\n", wFilePath.c_str());
            return false;
        }
    } else {
        wFilePath = IncludeTrailingPathDelimiter(wFilePath);
        string displayName = fileAsset.GetDisplayName();
        if (displayName.empty()) {
            printf("RecvFile displayName is null.\n");
            return false;
        }
        wFilePath += displayName;
    }
    return true;
}

static int32_t RecvFile(const ExecEnv &env, const FileAsset &fileAsset)
{
    std::string wFilePath;
    if (!GetWriteFilePath(env, fileAsset, wFilePath)) {
        return Media::E_ERR;
    }
    auto wfd = open(wFilePath.c_str(), O_CREAT | O_WRONLY | O_CLOEXEC, OPEN_MODE);
    if (wfd <= 0) {
        printf("%s open file failed. errno:%d, fileName:%s\n", STR_FAIL.c_str(), errno, wFilePath.c_str());
        return Media::E_ERR;
    }
    auto rfd = UserFileClientEx::Open(fileAsset.GetUri(), Media::MEDIA_FILEMODE_READONLY);
    if (rfd <= 0) {
        printf("%s open failed. uri:%s\n", STR_FAIL.c_str(), fileAsset.GetUri().c_str());
        close(wfd);
        return Media::E_ERR;
    }
    auto ret = MediaFileUtils::CopyFile(rfd, wfd);
    if (!ret) {
        printf("%s receive data failed. uri:%s\n", STR_FAIL.c_str(), fileAsset.GetUri().c_str());
    } else {
        printf("%s\n", wFilePath.c_str());
    }
    UserFileClientEx::Close(fileAsset.GetUri(), rfd, Media::MEDIA_FILEMODE_READONLY);
    close(wfd);
    return ret ? Media::E_OK : Media::E_ERR;
}

static int32_t RecvAsset(const ExecEnv &env, const std::string &tableName, const std::string &uri)
{
    if (tableName.empty()) {
        printf("%s can not get query table, uri:%s\n", STR_FAIL.c_str(), uri.c_str());
        return Media::E_ERR;
    }
    printf("Table Name: %s\n", tableName.c_str());
    std::shared_ptr<DataShare::DataShareResultSet> resultSet;
    auto res = UserFileClientEx::Query(tableName, uri, resultSet);
    std::shared_ptr<FetchResult<FileAsset>> fetchResult = std::make_shared<FetchResult<FileAsset>>(resultSet);
    fetchResult->SetResultNapiType(ResultNapiType::TYPE_USERFILE_MGR);
    if (res != Media::E_OK) {
        printf("%s query issue. tableName:%s, uri:%s\n", STR_FAIL.c_str(), tableName.c_str(), uri.c_str());
        return Media::E_ERR;
    }
    if (fetchResult == nullptr) {
        return Media::E_OK;
    }
    auto count = fetchResult->GetCount();
    if (count > 1) {
        printf("%s get result count=%d, failed, uri:%s\n", STR_FAIL.c_str(), count, uri.c_str());
    } else if (count == 0) {
        printf("WARN: get result count 0, uri:%s\n", uri.c_str());
    } else {
        auto fileAsset = fetchResult->GetFirstObject();
        RecvFile(env, *fileAsset);
    }
    fetchResult->Close();
    return Media::E_OK;
}

static int32_t RecvAssets(const ExecEnv &env, const std::string &tableName)
{
    if (tableName.empty()) {
        printf("%s table name is empty.\n", STR_FAIL.c_str());
        return Media::E_ERR;
    }
    printf("Table Name: %s\n", tableName.c_str());
    std::shared_ptr<DataShare::DataShareResultSet> resultSet;
    auto res = UserFileClientEx::Query(tableName, "", resultSet);
    std::shared_ptr<FetchResult<FileAsset>> fetchResult = std::make_shared<FetchResult<FileAsset>>(resultSet);
    fetchResult->SetResultNapiType(ResultNapiType::TYPE_USERFILE_MGR);
    if (res != Media::E_OK) {
        printf("%s query issue. tableName:%s\n", STR_FAIL.c_str(), tableName.c_str());
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
    if (env.recvParam.isRecvAll) {
        bool hasError = false;
        auto tables = UserFileClientEx::GetSupportTables();
        for (auto tableName : tables) {
            if (RecvAssets(env, tableName) != Media::E_OK) {
                hasError = true;
            }
            printf("\n");
        }
        return hasError ? Media::E_ERR : Media::E_OK;
    } else {
        string tableName = UserFileClientEx::GetTableNameByUri(env.recvParam.recvUri);
        return RecvAsset(env, tableName, env.recvParam.recvUri);
    }
}
} // namespace MediaTool
} // namespace Media
} // namespace OHOS

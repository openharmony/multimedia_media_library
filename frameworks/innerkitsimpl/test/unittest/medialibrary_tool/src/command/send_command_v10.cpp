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
#include "command/send_command_v10.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "constant.h"
#include "directory_ex.h"
#include "media_file_utils.h"
#include "medialibrary_errno.h"
#include "mimetype_utils.h"
#include "userfile_client_ex.h"
#include "utils/file_utils.h"

namespace OHOS {
namespace Media {
namespace MediaTool {
struct FileInfo {
    Media::MediaType mediaType {Media::MediaType::MEDIA_TYPE_DEFAULT};
    std::string displayName;
    std::string path;
    std::string uri;
    int32_t id {-1};
    bool toBeRemove {false};
    int32_t result {-1};
    [[nodiscard]] std::string ToStr() const
    {
        std::string str;
        str.append("mediaType:");
        str.append(std::to_string(static_cast<uint32_t>(mediaType)));
        str.append(", displayName:");
        str.append(displayName);
        str.append(", path:");
        str.append(path);
        str.append(", uri:");
        str.append(uri);
        str.append(", id:");
        str.append(std::to_string(id));
        return str;
    }
};

int32_t GetFileInfo(const ExecEnv &env, const std::string &path, std::vector<FileInfo> &fileInfos)
{
    std::string extension = ExtractFileExt(path);
    std::string mimeType = MimeTypeUtils::GetMimeTypeFromExtension(extension);
    FileInfo fileInfo;
    fileInfo.mediaType = MimeTypeUtils::GetMediaTypeFromMimeType(mimeType);
    fileInfo.displayName = ExtractFileName(path);
    fileInfo.path = path;
    fileInfo.result = Media::E_ERR;
    fileInfos.push_back(fileInfo);
    return Media::E_OK;
}

int32_t GetDirInfo(const ExecEnv &env, const std::string &path, std::vector<FileInfo> &fileInfos)
{
    std::vector<std::string> files;
    GetDirFiles(path, files);
    for (auto &file : files) {
        auto ret = GetFileInfo(env, file, fileInfos);
        if (ret != Media::E_OK) {
            printf("%s get dir information failed. ret:%d, file:%s\n", STR_FAIL.c_str(), ret, file.c_str());
            return ret;
        }
    }
    return Media::E_OK;
}

void RemoveFiles(const ExecEnv &env, std::vector<FileInfo> &fileInfos)
{
    for (auto &fileInfo : fileInfos) {
        if (fileInfo.result != Media::E_OK) {
            continue;
        }
        if (!fileInfo.toBeRemove) {
            continue;
        }
        RemoveFile(fileInfo.path);
    }
    fileInfos.clear();
}

int32_t CreateRecord(const ExecEnv &env, FileInfo &fileInfo)
{
    const MediaType mediaType = fileInfo.mediaType;
    const std::string displayName = fileInfo.displayName;
    auto fileId = UserFileClientEx::Insert(mediaType, displayName);
    if (fileId <= 0) {
        printf("%s create record failed. fileId:%d, fileInfo:%s\n", STR_FAIL.c_str(), fileId, fileInfo.ToStr().c_str());
        return Media::E_ERR;
    }
    fileInfo.uri = MediaFileUtils::GetFileMediaTypeUriV10(mediaType, env.networkId) + SLASH_CHAR + to_string(fileId);
    fileInfo.id = fileId;
    return Media::E_OK;
}

int32_t WriteFile(const ExecEnv &env, const FileInfo &fileInfo)
{
    auto rfd = open(fileInfo.path.c_str(), O_RDONLY | O_CLOEXEC);
    if (rfd < 0) {
        printf("%s open file failed. rfd:%d, path:%s\n", STR_FAIL.c_str(), rfd, fileInfo.path.c_str());
        return Media::E_ERR;
    }
    auto wfd = UserFileClientEx::Open(fileInfo.uri, Media::MEDIA_FILEMODE_WRITETRUNCATE);
    if (wfd <= 0) {
        printf("%s open failed. wfd:%d, uri:%s\n", STR_FAIL.c_str(), wfd, fileInfo.uri.c_str());
        close(rfd);
        return Media::E_ERR;
    }
    auto ret = FileUtils::SendData(rfd, wfd);
    if (!ret) {
        printf("%s send data failed. rfd:%d, wfd:%d\n", STR_FAIL.c_str(), rfd, wfd);
    }
    UserFileClientEx::Close(fileInfo.uri, wfd, Media::MEDIA_FILEMODE_WRITETRUNCATE);
    close(rfd);
    return ret ? Media::E_OK : Media::E_ERR;
}

int32_t SendFile(const ExecEnv &env, FileInfo &fileInfo)
{
    if (CreateRecord(env, fileInfo) != Media::E_OK) {
        return Media::E_ERR;
    }
    if (fileInfo.uri.find(MEDIALIBRARY_DATA_ABILITY_PREFIX) != 0) {
        printf("%s uri issue. uri:%s\n", STR_FAIL.c_str(), fileInfo.uri.c_str());
        return Media::E_ERR;
    }
    int32_t res = WriteFile(env, fileInfo);
    if (res != Media::E_OK) {
        return res;
    }
    fileInfo.result = Media::E_OK;
    return Media::E_OK;
}

int32_t SendFiles(const ExecEnv &env, std::vector<FileInfo> &fileInfos)
{
    for (auto &fileInfo : fileInfos) {
        int32_t ret = SendFile(env, fileInfo);
        if (ret != Media::E_OK) {
            return ret;
        }
        fileInfo.toBeRemove = true;
        printf("%s\n", fileInfo.uri.c_str());
    }
    return Media::E_OK;
}

int32_t SendCommandV10::Start(const ExecEnv &env)
{
    std::vector<FileInfo> fileInfos;
    auto ret = (env.isFile) ? GetFileInfo(env, env.path, fileInfos) : GetDirInfo(env, env.path, fileInfos);
    if (ret != Media::E_OK) {
        printf("%s get file information failed. ret:%d\n", STR_FAIL.c_str(), ret);
        return ret;
    }
    ret = SendFiles(env, fileInfos);
    RemoveFiles(env, fileInfos);
    return ret;
}
} // namespace MediaTool
} // namespace Media
} // namespace OHOS

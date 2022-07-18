/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_INNERKITSIMPL_MEDIA_LIBRARY_INCLUDE_MEDIA_FILE_UTILS_H_
#define FRAMEWORKS_INNERKITSIMPL_MEDIA_LIBRARY_INCLUDE_MEDIA_FILE_UTILS_H_

#include <string>
#include <sys/types.h>

namespace OHOS {
namespace Media {
static const mode_t CHOWN_RWX_USR_GRP = 02770;
static const mode_t CHOWN_RW_USR_GRP = 0660;

/**
 * @brief Utility class for file operations
 *
 * @since 1.0
 * @version 1.0
 */
class MediaFileUtils {
public:
    static bool IsFileExists(const std::string& fileName);
    static bool CreateFile(const std::string& fileName);
    static bool DeleteFile(const std::string& fileName);
    static bool DeleteDir(const std::string& dirName);
    static std::string GetFilename(const std::string& filePath);
    static std::string GetParentPath(const std::string &path);
    static bool IsDirectory(const std::string& dirName);
    static bool MoveFile(const std::string& oldPath, const std::string& newPath);
    static bool CopyFile(const std::string& filePath, const std::string& newPath);
    static bool RenameDir(const std::string& oldPath, const std::string& newPath);
    static bool CreateDirectory(const std::string& dirPath);
    static bool CheckDisplayName(std::string displayName);
    static bool CheckTitle(std::string title);
    static int64_t GetAlbumDateModified(const std::string &albumPath);
    static int64_t UTCTimeSeconds();
    static std::string GetNetworkIdFromUri(const std::string &uri);
    static std::string UpdatePath(const std::string &path, const std::string &uri);
    static std::string GetFileMediaTypeUri(int32_t mediaType, const std::string &networkId);
    static std::string GetUriByNameAndId(const std::string &displayName, const std::string &networkId, int32_t id);
};
} // namespace Media
} // namespace  OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_MEDIA_LIBRARY_INCLUDE_MEDIA_FILE_UTILS_H_

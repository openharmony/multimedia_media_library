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
#include <unordered_set>

#include "userfile_manager_types.h"

namespace OHOS::Media {

const std::string MEDIA_FILEMODE_READONLY = "r";
const std::string MEDIA_FILEMODE_WRITEONLY = "w";
const std::string MEDIA_FILEMODE_READWRITE = "rw";
const std::string MEDIA_FILEMODE_WRITETRUNCATE = "wt";
const std::string MEDIA_FILEMODE_WRITEAPPEND = "wa";
const std::string MEDIA_FILEMODE_READWRITETRUNCATE = "rwt";
const std::string MEDIA_FILEMODE_READWRITEAPPEND = "rwa";
const std::unordered_set<std::string> MEDIA_OPEN_MODES = {
    MEDIA_FILEMODE_READONLY,
    MEDIA_FILEMODE_WRITEONLY,
    MEDIA_FILEMODE_READWRITE,
    MEDIA_FILEMODE_WRITETRUNCATE,
    MEDIA_FILEMODE_WRITEAPPEND,
    MEDIA_FILEMODE_READWRITETRUNCATE,
    MEDIA_FILEMODE_READWRITEAPPEND
};

/**
 * @brief Utility class for file operations
 *
 * @since 1.0
 * @version 1.0
 */
class MediaFileUtils {
public:
    static bool IsFileExists(const std::string &fileName);
    static bool IsDirEmpty(const std::string &path);
    static bool CreateFile(const std::string &filePath);
    static bool DeleteFile(const std::string &fileName);
    static bool DeleteDir(const std::string &dirName);
    static int32_t RemoveDirectory(const std::string &path);
    static std::string GetFilename(const std::string &filePath);
    static std::string GetFirstDentry(const std::string &path);
    static std::string GetLastDentry(const std::string &path);
    static bool IsDirectory(const std::string &dirName);
    static std::string GetFirstDirName(const std::string &filePath);
    static bool MoveFile(const std::string &oldPath, const std::string &newPath);
    static bool CopyFile(const std::string &filePath, const std::string &newPath);
    static bool RenameDir(const std::string &oldPath, const std::string &newPath);
    static bool CreateDirectory(const std::string &dirPath);
    static int32_t CheckStringSize(const std::string &str, const size_t max);
    static int32_t CheckAlbumName(const std::string &albumName);
    static int32_t CheckDisplayName(const std::string &displayName);
    static int32_t CheckTitle(const std::string &title);
    static int64_t GetAlbumDateModified(const std::string &albumPath);
    static int64_t UTCTimeSeconds();
    static std::string GetIdFromUri(const std::string &uri);
    static std::string GetNetworkIdFromUri(const std::string &uri);
    static std::string UpdatePath(const std::string &path, const std::string &uri);
    static std::string GetFileMediaTypeUri(int32_t mediaType, const std::string &networkId);
    static std::string GetUriByNameAndId(const std::string &displayName, const std::string &networkId, int32_t id);
    static MediaType GetMediaType(const std::string &filePath);
    static std::string SplitByChar(const std::string &str, const char split);
    static std::string GetExtensionFromPath(const std::string &path);
    static int32_t OpenFile(const std::string &path, const std::string &mode);
    static int32_t CreateAsset(const std::string &filePath);
    static int32_t ModifyAsset(const std::string &oldPath, const std::string &newPath);
    static int32_t DeleteAsset(const std::string &filePath);
    static int32_t OpenAsset(const std::string &filePath, const std::string &mode);
    static int32_t CloseAsset(int32_t fd);
    static std::string GetMediaTypeUri(MediaType mediaType);
    static void GenTypeMaskFromArray(const std::vector<uint32_t> types, std::string &typeMask);
    static void UriAddFragmentTypeMask(std::string &uri, const std::string &typeMask);
    static void AppendFetchOptionSelection(std::string &selection, const std::string &newCondition);
    static std::string DealWithUriWithName(std::string str);
};
} // namespace OHOS::Media

#endif // FRAMEWORKS_INNERKITSIMPL_MEDIA_LIBRARY_INCLUDE_MEDIA_FILE_UTILS_H_

/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

const int VIRTUAL_ID_DIVIDER = 5;
const int PHOTO_VIRTUAL_IDENTIFIER = 4;
const int AUDIO_VIRTUAL_IDENTIFIER = 3;
const int FILE_VIRTUAL_IDENTIFIER = 2;
const int CAMERA_SHOT_KEY_SIZE = 30;

enum TrashType {
    NOT_TRASHED = 0,
    TRASHED_ASSET,
    TRASHED_DIR,
    TRASHED_DIR_CHILD
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
    static std::string GetFileName(const std::string &filePath);
    static std::string GetFirstDentry(const std::string &path);
    static std::string GetLastDentry(const std::string &path);
    static std::string GetParentPath(const std::string &path);
    static std::string GetTitleFromDisplayName(const std::string &displayName);
    static bool IsDirectory(const std::string &dirName);
    static std::string GetFirstDirName(const std::string &filePath);
    static bool MoveFile(const std::string &oldPath, const std::string &newPath);
    static bool CopyFile(const std::string &filePath, const std::string &newPath);
    static bool RenameDir(const std::string &oldPath, const std::string &newPath);
    static bool CreateDirectory(const std::string &dirPath);
    static int32_t CheckStringSize(const std::string &str, const size_t max);
    static int32_t CheckAlbumName(const std::string &albumName);
    static int32_t CheckDentryName(const std::string &dentryName);
    static int32_t CheckDisplayName(const std::string &displayName);
    static int32_t CheckFileDisplayName(const std::string &displayName);
    static int32_t CheckRelativePath(const std::string &relativePath);
    static void FormatRelativePath(std::string &relativePath);
    static void GetRootDirFromRelativePath(const std::string &relativePath, std::string &rootDir);
    static int64_t GetAlbumDateModified(const std::string &albumPath);
    static int64_t UTCTimeSeconds();
    static std::string GetIdFromUri(const std::string &uri);
    static std::string GetNetworkIdFromUri(const std::string &uri);
    static std::string UpdatePath(const std::string &path, const std::string &uri);
    static std::string GetFileMediaTypeUri(int32_t mediaType, const std::string &networkId);
    static std::string GetFileMediaTypeUriV10(int32_t mediaType, const std::string &networkId);
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
    static std::string GetMediaTypeUriV10(MediaType mediaType);
    static void AppendFetchOptionSelection(std::string &selection, const std::string &newCondition);
    static bool CheckMode(const std::string &mode);
    static size_t FindIgnoreCase(const std::string &str, const std::string &key);
    static int64_t GetVirtualIdByType(int32_t id, MediaType type);
    static double GetRealIdByTable(int32_t virtualId, const std::string &tableName);
    static std::string GetVirtualUriFromRealUri(const std::string &uri, const std::string &extrUri = "");
    static std::string GetRealUriFromVirtualUri(const std::string &uri);
    static bool StartsWith(const std::string &str, const std::string &prefix);
    static void UriAppendKeyValue(std::string &uri, const std::string &key, std::string value = "10");
    static std::string GetExtraUri(const std::string &displayName, const std::string &path);
    static std::string GetUriByExtrConditions(const std::string &prefix, const std::string &fileId,
        const std::string &suffix = "");
    static std::string Encode(const std::string &uri);
#ifdef MEDIALIBRARY_COMPATIBILITY
    static std::string GetTableFromVirtualUri(const std::string &uri);
#endif
    static bool IsUriV10(const std::string &mediaType);
    static bool IsFileTablePath(const std::string &path);
    static bool IsPhotoTablePath(const std::string &path);
};
} // namespace OHOS::Media

#endif // FRAMEWORKS_INNERKITSIMPL_MEDIA_LIBRARY_INCLUDE_MEDIA_FILE_UTILS_H_

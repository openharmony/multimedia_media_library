/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#ifndef FRAMEWORKS_SERVICES_MEDIA_LIBRARY_EXTENTION_UTILS_H_
#define FRAMEWORKS_SERVICES_MEDIA_LIBRARY_EXTENTION_UTILS_H_

#include "abs_shared_result_set.h"
#include "datashare_result_set.h"
#include "file_access_extension_info.h"
#include "file_filter.h"
#include "result_set_utils.h"
#include "uri.h"

namespace OHOS {
namespace Media {
template<typename ResultSet>
static inline std::string GetStringVal(const std::string &field, const ResultSet &result)
{
    return get<std::string>(ResultSetUtils::GetValFromColumn(field, result, TYPE_STRING));
}
template<typename ResultSet>
static inline int32_t GetInt32Val(const std::string &field, const ResultSet &result)
{
    return get<int32_t>(ResultSetUtils::GetValFromColumn(field, result, TYPE_INT32));
}
template<typename ResultSet>
static inline int64_t GetInt64Val(const std::string &field, const ResultSet &result)
{
    return get<int64_t>(ResultSetUtils::GetValFromColumn(field, result, TYPE_INT64));
}

// root dirs
const std::vector<std::string> directoryEnumValues {
    "Camera/",
    "Videos/",
    "Pictures/",
    "Audios/",
    "Documents/",
    "Download/"
};
// parent id is root path
const int32_t ROOT_PARENT_ID = 0;
// device virtual root node
static const std::string MEDIALIBRARY_ROOT = "/root";
static const std::string MEDIALIBRARY_LOCAL_DEVICE_NAME = "LOCAL";
// mimetype prefix
const std::string DEFAULT_AUDIO_MIME_TYPE_PREFIX = "audio/";
const std::string DEFAULT_VIDEO_MIME_TYPE_PREFIX = "video/";
const std::string DEFAULT_IMAGE_MIME_TYPE_PREFIX = "image/";
const std::string DEFAULT_FILE_MIME_TYPE_PREFIX = "file/";
enum MediaFileUriType {
    URI_ROOT,
    URI_MEDIA_ROOT,
    URI_FILE_ROOT,
    URI_DIR,
    URI_ALBUM,
};
class MediaFileExtentionUtils {
public:
    static bool CheckUriValid(const std::string &uri);
    static bool CheckDistributedUri(const std::string &uri);
    static int32_t CheckUriSupport(const std::string &uri);
    static std::shared_ptr<NativeRdb::ResultSet> GetResultSetFromDb(std::string field, const std::string &uri);
    static bool IsFileExistInDb(const std::string &path);
    static int32_t ResolveUri(const FileAccessFwk::FileInfo &fileInfo, MediaFileUriType &uriType);
    static bool CheckValidDirName(const std::string &displayName);
    static int32_t CheckMkdirValid(MediaFileUriType uriType, const std::string &parentUriStr,
        const std::string &displayName);
    static bool GetAlbumRelativePathFromDB(const std::string &selectUri, std::string &relativePath);
    static int32_t Move(const Uri &sourceFileUri, const Uri &targetParentUri, Uri &newFileUri);
    static int32_t Rename(const Uri &sourceFileUri, const std::string &displayName, Uri &newFileUri);
    static int32_t ListFile(const FileAccessFwk::FileInfo &parentInfo, const int64_t offset, const int64_t maxCount,
        const DistributedFS::FileFilter &filter, std::vector<FileAccessFwk::FileInfo> &fileList);
    static int32_t ScanFile(const FileAccessFwk::FileInfo &parentInfo, const int64_t offset, const int64_t maxCount,
        const DistributedFS::FileFilter &filter, std::vector<FileAccessFwk::FileInfo> &fileList);
    static int32_t GetRoots(std::vector<FileAccessFwk::RootInfo> &rootList);
    static int Access(const Uri &uri, bool &isExist);
    static int UriToFileInfo(const Uri &selectFile, FileAccessFwk::FileInfo &fileInfo);
};
} // Media
} // OHOS

#endif // FRAMEWORKS_SERVICES_MEDIA_LIBRARY_EXTENTION_UTILS_H_

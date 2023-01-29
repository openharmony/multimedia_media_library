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
#include "file_access_extension_info.h"
#include "file_filter.h"
#include "uri.h"

namespace OHOS {
namespace Media {
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
    static int32_t ResolveUri(const FileAccessFwk::FileInfo &fileInfo, MediaFileUriType &uriType);
    static bool CheckValidDirName(const std::string &displayName);
    static int32_t CheckMkdirValid(MediaFileUriType uriType, const std::string &parentUriStr,
        const std::string &displayName);
    static bool GetAlbumRelativePathFromDB(const std::string &selectUri, const std::string &networkId,
        std::string &relativePath);
    static std::shared_ptr<NativeRdb::AbsSharedResultSet> GetFileFromDB(const std::string &selectUri,
        const std::string &networkId);

    static int32_t OpenFile(const Uri &uri, const int flags, int &fd);
    static int32_t CreateFile(const Uri &parentUri, const std::string &displayName,  Uri &newFileUri);
    static int32_t Mkdir(const Uri &parentUri, const std::string &displayName, Uri &newFileUri);
    static int32_t Delete(const Uri &sourceFileUri);
    static int32_t Move(const Uri &sourceFileUri, const Uri &targetParentUri, Uri &newFileUri);
    static int32_t Rename(const Uri &sourceFileUri, const std::string &displayName, Uri &newFileUri);
    static int32_t ListFile(const FileAccessFwk::FileInfo &parentInfo, const int64_t offset, const int64_t maxCount,
        const DistributedFS::FileFilter &filter, std::vector<FileAccessFwk::FileInfo> &fileList);
    static int32_t ScanFile(const FileAccessFwk::FileInfo &parentInfo, const int64_t offset, const int64_t maxCount,
        const DistributedFS::FileFilter &filter, std::vector<FileAccessFwk::FileInfo> &fileList);
    static int32_t GetRoots(std::vector<FileAccessFwk::RootInfo> &rootList);
    static int Access(const Uri &uri, bool &isExist);
};
} // Media
} // OHOS

#endif // FRAMEWORKS_SERVICES_MEDIA_LIBRARY_EXTENTION_UTILS_H_

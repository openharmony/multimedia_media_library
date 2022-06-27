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
#include "uri.h"

namespace OHOS {
namespace Media {
// parent id is root path
const int32_t ROOT_PARENT_ID = 0;
// device virtual root node
static const std::string MEDIALIBRARY_ROOT = "/root";
static const std::string MEDIALIBRARY_LOCAL_DEVICE_NAME = "LOCAL";
// fileextension fileinfo mode
static const std::string MEDIA_FILE_EXT_MODE_FOLDER = "folder";
static const std::string MEDIA_FILE_EXT_MODE_FILE = "file";
enum MediaFileUriType {
    URI_ROOT,
    URI_ALBUM,
    URI_FILE,
    URI_DIR,
};
class MediaFileExtentionUtils {
public:
    static bool CheckUriValid(const std::string &uri);
    static bool CheckDistributedUri(const std::string &uri);
    static MediaFileUriType ResolveUri(const std::string &uri);
    static bool CheckValidDirName(const std::string &displayName);
    static bool GetAlbumRelativePathFromDB(const std::string &selectUri, const std::string &networkId,
        std::string &relativePath);
    static std::shared_ptr<NativeRdb::AbsSharedResultSet> GetFileFromDB(const std::string &selectUri,
        const std::string &networkId);
    static int32_t Move(const Uri &sourceFileUri, const Uri &targetParentUri, Uri &newFileUri);
    static int32_t Rename(const Uri &sourceFileUri, const std::string &displayName, Uri &newFileUri);
    static int32_t ListFile(const std::string &selectUri, std::vector<FileAccessFwk::FileInfo> &fileList);
    static void GetRoots(std::vector<FileAccessFwk::DeviceInfo> &deviceList);
};
} // Media
} // OHOS

#endif // FRAMEWORKS_SERVICES_MEDIA_LIBRARY_EXTENTION_UTILS_H_

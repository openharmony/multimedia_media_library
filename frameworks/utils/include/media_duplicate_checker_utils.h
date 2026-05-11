/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIALIBRARY_MEDIA_DUPLICATE_CHECKER_UTILS_H
#define OHOS_MEDIALIBRARY_MEDIA_DUPLICATE_CHECKER_UTILS_H

#include <string>
#include "values_bucket.h"
 
namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))

class MediaDuplicateCheckerUtils {
public:
    EXPORT static std::string replaceFilename(const std::string& path, const std::string& newName);
    EXPORT static int32_t getAlbumLpathByAlbumId(const std::string &albumId, std::string &lpath);
    EXPORT static int32_t getAlbumActualPathByAlbumId(const std::string &albumId, std::string &actualPath);
    EXPORT static int32_t checkAlbumNameDuplicateInDB(const std::string &newAlbumName);
    EXPORT bool checkNameValidForMediaLibrary(const std::string &name);
    EXPORT static int32_t checkAlbumNameDuplicate(const std::string &albumId, const std::string &newAlbumName);
    EXPORT static int32_t checkPhotoNameDuplicate(const std::string &fileId, const std::string &newName);
    EXPORT static int32_t checkDirectoryNameConflict(const NativeRdb::ValuesBucket& newAlbumValues);
private:
    static int32_t getAlbumPathAndDisplayNameByFileId(
        const std::string &fileId, std::string &actualPath, std::string &displayName);
};
} // namespace Media
} // namespace OHOS

#endif // OHOS_MEDIALIBRARY_MEDIA_DUPLICATE_CHECKER_UTILS_H
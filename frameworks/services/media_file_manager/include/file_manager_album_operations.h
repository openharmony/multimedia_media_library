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
#ifndef MEDIALIBRARY_FILE_MANAGER_ALBUM_OPERATIONS_H
#define MEDIALIBRARY_FILE_MANAGER_ALBUM_OPERATIONS_H
#include <string>

#include "asset_accurate_refresh.h"

namespace OHOS::Media {

class FileManagerAlbumOperations {
public:
    // 重命名文管相册
    EXPORT static int32_t RenameFileManagerAlbum(
        const string &oldAlbumPath, const int32_t oldAlbumId, const string &newAlbumName);
};
} // namespace OHOS::Media
#endif // MEDIALIBRARY_FILE_MANAGER_ALBUM_OPERATIONS_H
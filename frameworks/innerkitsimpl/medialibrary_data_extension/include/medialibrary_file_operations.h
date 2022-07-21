/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIALIBRARY_FILE_OPERATIONS_H
#define OHOS_MEDIALIBRARY_FILE_OPERATIONS_H

#include <string>
#include <unordered_map>

#include "abs_shared_result_set.h"
#include "dir_asset.h"
#include "medialibrary_command.h"

namespace OHOS {
namespace Media {
class MediaLibraryFileOperations {
public:
    static int32_t HandleFileOperation(MediaLibraryCommand &cmd);

    static int32_t CreateFileOperation(MediaLibraryCommand &cmd);
    static int32_t CloseFileOperation(MediaLibraryCommand &cmd);
    static int32_t GetAlbumCapacityOperation(MediaLibraryCommand &cmd);
    static int32_t ModifyFileOperation(MediaLibraryCommand &cmd);
    static int32_t DeleteFileOperation(MediaLibraryCommand &cmd,
        const std::unordered_map<std::string, DirAsset> &dirQuerySetMap);
    static int32_t IsDirectoryOperation(MediaLibraryCommand &cmd);
    static std::shared_ptr<NativeRdb::AbsSharedResultSet> QueryFileOperation(MediaLibraryCommand &cmd,
        std::vector<std::string> columns);

private:
    static std::shared_ptr<NativeRdb::AbsSharedResultSet> QueryFavFiles(MediaLibraryCommand &cmd);
    static std::shared_ptr<NativeRdb::AbsSharedResultSet> QueryTrashFiles(MediaLibraryCommand &cmd);
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_FILE_OPERATIONS_H

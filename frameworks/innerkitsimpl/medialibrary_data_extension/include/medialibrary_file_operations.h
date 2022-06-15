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

#include "datashare_values_bucket.h"
#include "dir_asset.h"
#include "file_asset.h"
#include "imedia_scanner_client.h"
#include "media_data_ability_const.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_file_db.h"
#include "medialibrary_thumbnail.h"
#include "medialibrary_command.h"
#include "medialibrary_unistore_manager.h"
#include "native_album_asset.h"
#include "rdb_store.h"
#include "rdb_utils.h"
#include "values_bucket.h"

namespace OHOS {
namespace Media {
class MediaLibraryFileOperations {
public:
    MediaLibraryFileOperations();
    ~MediaLibraryFileOperations() = default;

    int32_t HandleCreateAsset(MediaLibraryCommand &cmd);
    int32_t HandleCloseAsset(MediaLibraryCommand &cmd);
    int32_t HandleGetAlbumCapacity(MediaLibraryCommand &cmd);
    int32_t HandleFileOperation(MediaLibraryCommand &cmd, const unordered_map<string, DirAsset> &dirQuerySetMap);
    int32_t HandleModifyAsset(MediaLibraryCommand &cmd);
    int32_t HandleDeleteAsset(MediaLibraryCommand &cmd, const unordered_map<string, DirAsset> &dirQuerySetMap);
    int32_t HandleIsDirectoryAsset(MediaLibraryCommand &cmd);

private:
    std::shared_ptr<NativeRdb::AbsSharedResultSet> QueryFiles(MediaLibraryCommand &cmd);
    std::shared_ptr<NativeRdb::AbsSharedResultSet> QueryFavFiles(MediaLibraryCommand &cmd);
    std::shared_ptr<NativeRdb::AbsSharedResultSet> QueryTrashFiles(MediaLibraryCommand &cmd);
    std::shared_ptr<MediaLibraryUnistore> uniStore_{nullptr};
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_FILE_OPERATIONS_H
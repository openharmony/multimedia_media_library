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

#ifndef OHOS_MEDIALIBRARY_SMARTALBUMMAP_DB_H
#define OHOS_MEDIALIBRARY_SMARTALBUMMAP_DB_H

#include <string>
#include "medialibrary_db_const.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_store.h"
#include "sys/stat.h"
#include "datashare_values_bucket.h"

namespace OHOS {
namespace Media {
using namespace OHOS::NativeRdb;
using namespace std;
const int32_t NOT_ISTRASH = 0;
const int32_t ASSET_ISTRASH = 1;
const int32_t DIR_ISTRASH = 2;
const int32_t CHILD_ISTRASH = 3;
class MediaLibrarySmartAlbumMapDb {
public:
    MediaLibrarySmartAlbumMapDb() = default;
    ~MediaLibrarySmartAlbumMapDb() = default;
    int32_t DeleteSmartAlbumMapInfo(const int32_t albumId, const int32_t assetId, const shared_ptr<RdbStore> &rdbStore);
    int32_t DeleteAllSmartAlbumMapInfo(const int32_t albumId, const shared_ptr<RdbStore> &rdbStore);
    int32_t DeleteAllAssetsMapInfo(const int32_t assetId, const shared_ptr<RdbStore> &rdbStore);
    int32_t UpdateSmartAlbumMapInfo(const ValuesBucket &values, const shared_ptr<RdbStore> &rdbStore);
    int64_t InsertSmartAlbumMapInfo(const ValuesBucket &values, const shared_ptr<RdbStore> &rdbStore);
    int32_t UpdateAssetTrashInfo(const int32_t &assetId,
        const int64_t &trashDate, const shared_ptr<RdbStore> &rdbStore, string &recyclePath, const string &oldPath);
    int32_t UpdateSameNameInfo(const int32_t &assetId,
        const string &displayName, const string &path, const shared_ptr<RdbStore> &rdbStore);
    int32_t UpdateParentDirRecycleInfo(const int32_t &assetId, const int32_t &parentId,
        const string &parentName, const shared_ptr<RdbStore> &rdbStore);
    int32_t UpdateChildFileRecycleInfo(const int32_t &assetId,
        const string &parentName, const shared_ptr<RdbStore> &rdbStore);
    int32_t UpdateChildPathInfo(const int32_t &assetId,
        const string &path, const string &relativePath, const int32_t isTrash, const shared_ptr<RdbStore> &rdbStore);
    int32_t DeleteTrashInfo(const int32_t &assetId, const shared_ptr<RdbStore> &rdbStore);
    int32_t UpdateFavoriteInfo(const int32_t &assetId,
        const OHOS::NativeRdb::ValuesBucket &values, const shared_ptr<RdbStore> &rdbStore);
    int32_t UpdateRecycleInfo(const int32_t &assetId, const shared_ptr<RdbStore> &rdbStore, const string &realPath);
    int32_t UpdateDirTrashInfo(const int32_t &assetId,
        const int64_t &trashDate, const shared_ptr<RdbStore> &rdbStore, string &recyclePath, const string &oldPath);
    int32_t UpdateChildTrashInfo(const int32_t &assetId,
        const shared_ptr<RdbStore> &rdbStore, const int64_t &trashDate);
    int32_t UpdateChildRecycleInfo(const int32_t &assetId,
        const shared_ptr<RdbStore> &rdbStore, const int64_t &recycleDate);
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_SMARTALBUMMAP_DB_H

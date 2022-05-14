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

#include "medialibrary_smartalbum_map_operations.h"
#include "media_log.h"
using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;

namespace OHOS {
namespace Media {
int32_t InsertAlbumAssetsInfoUtil(const DataShareValuesBucket &valuesBucket,
                                  shared_ptr<RdbStore> rdbStore,
                                  const MediaLibrarySmartAlbumMapDb &smartAlbumMapDbOprn)
{
    DataShareValuesBucket values = const_cast<DataShareValuesBucket &>(valuesBucket);
    int32_t insertResult = const_cast<MediaLibrarySmartAlbumMapDb &>(smartAlbumMapDbOprn)
    .InsertSmartAlbumMapInfo(values, rdbStore);
    return insertResult;
}
int32_t RemoveAlbumAssetsInfoUtil(const DataShareValuesBucket &valuesBucket,
                                  shared_ptr<RdbStore> rdbStore,
                                  const MediaLibrarySmartAlbumMapDb &smartAlbumMapDbOprn)
{
    DataShareValuesBucket values = const_cast<DataShareValuesBucket &>(valuesBucket);
    DataShareValueObject valueObject;
    int32_t albumId = 0;
    int32_t assetId = 0;
    if (values.GetObject(SMARTALBUMMAP_DB_ALBUM_ID, valueObject)) {
        valueObject.GetInt(albumId);
    }
    if (values.GetObject(SMARTALBUMMAP_DB_ASSET_ID, valueObject)) {
        valueObject.GetInt(assetId);
    }
    MEDIA_ERR_LOG("mediasmartmap albumId = %{private}d", albumId);
    MEDIA_ERR_LOG("mediasmartmap albumId = %{private}d", assetId);
    int32_t deleteResult = const_cast<MediaLibrarySmartAlbumMapDb &>(smartAlbumMapDbOprn)
    .DeleteSmartAlbumMapInfo(albumId, assetId, rdbStore);
    return deleteResult;
}
int32_t MediaLibrarySmartAlbumMapOperations::HandleSmartAlbumMapOperations(const string &oprn,
                                                                           const DataShareValuesBucket &valuesBucket,
                                                                           const shared_ptr<RdbStore> &rdbStore)
{
    DataShareValuesBucket values = const_cast<DataShareValuesBucket &>(valuesBucket);
    MediaLibrarySmartAlbumMapDb smartAlbumMapDbOprn;
    int32_t errCode = DATA_ABILITY_FAIL;
    if (oprn == MEDIA_SMARTALBUMMAPOPRN_ADDSMARTALBUM) {
        errCode = InsertAlbumAssetsInfoUtil(values, rdbStore, smartAlbumMapDbOprn);
    } else if (oprn == MEDIA_SMARTALBUMMAPOPRN_REMOVESMARTALBUM) {
        errCode = RemoveAlbumAssetsInfoUtil(values, rdbStore, smartAlbumMapDbOprn);
    }
    return errCode;
}
} // namespace Media
} // namespace OHOS

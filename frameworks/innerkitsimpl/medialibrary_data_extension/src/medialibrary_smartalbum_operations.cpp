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
#define MLOG_TAG "SmartAlbum"

#include "medialibrary_smartalbum_operations.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_smartalbum_map_db.h"

using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;

namespace OHOS {
namespace Media {
int32_t InsertAlbumInfoUtil(const ValuesBucket &valuesBucket,
                            shared_ptr<RdbStore> rdbStore,
                            const MediaLibrarySmartAlbumDb &smartAlbumDbOprn)
{
    ValueObject valueObject;
    int32_t id = 0;
    int32_t insertId = const_cast<MediaLibrarySmartAlbumDb &>(smartAlbumDbOprn).
        InsertSmartAlbumInfo(valuesBucket, rdbStore);
    if (insertId > 0) {
        ValuesBucket values;
        values.PutInt(CATEGORY_SMARTALBUMMAP_DB_CATEGORY_ID, id);
        values.PutInt(CATEGORY_SMARTALBUMMAP_DB_ALBUM_ID, insertId);
        const_cast<MediaLibrarySmartAlbumDb &>(smartAlbumDbOprn).InsertCategorySmartAlbumInfo(values, rdbStore);
    }
    return insertId;
}
int32_t DeleteAlbumInfoUtil(const ValuesBucket &valuesBucket,
                            shared_ptr<RdbStore> rdbStore,
                            const MediaLibrarySmartAlbumDb &smartAlbumDbOprn)
{
    ValuesBucket values = const_cast<ValuesBucket &>(valuesBucket);
    ValueObject valueObject;
    int32_t albumId = 0;
    MediaLibrarySmartAlbumMapDb smartAlbumMapDbOprn;
    if (values.GetObject(SMARTALBUM_DB_ID, valueObject)) {
        valueObject.GetInt(albumId);
    }
    MEDIA_ERR_LOG("mediasmart albumId = %{private}d", albumId);

    int32_t deleteErrorCode = const_cast<MediaLibrarySmartAlbumDb &>(smartAlbumDbOprn)
    .DeleteSmartAlbumInfo(albumId, rdbStore);
    if (deleteErrorCode != -1) {
        smartAlbumMapDbOprn.DeleteAllSmartAlbumMapInfo(albumId, rdbStore);
    }
    return deleteErrorCode;
}

int32_t MediaLibrarySmartAlbumOperations::HandleSmartAlbumOperations(const string &oprn,
                                                                     const ValuesBucket &valuesBucket,
                                                                     const shared_ptr<RdbStore> &rdbStore)
{
    MEDIA_ERR_LOG("HandleSmartAlbumOperations");
    ValuesBucket values = const_cast<ValuesBucket &>(valuesBucket);
    MediaLibrarySmartAlbumDb smartAlbumDbOprn;
    int32_t errCode = E_FAIL;
    ValueObject valueObject;
    if (oprn == MEDIA_SMARTALBUMOPRN_CREATEALBUM) {
        errCode = InsertAlbumInfoUtil(values, rdbStore, smartAlbumDbOprn);
    } else if (oprn == MEDIA_SMARTALBUMOPRN_DELETEALBUM) {
        errCode = DeleteAlbumInfoUtil(values, rdbStore, smartAlbumDbOprn);
    }
    return errCode;
}
} // namespace Media
} // namespace OHOS

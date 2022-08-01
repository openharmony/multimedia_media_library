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

#include "medialibrary_smartalbum_db.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "rdb_utils.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
static const std::string SMARTALBUM_DB_COND = SMARTALBUM_DB_ID + " = ?";
int64_t MediaLibrarySmartAlbumDb::InsertSmartAlbumInfo(const ValuesBucket &values, const shared_ptr<RdbStore> &rdbStore)
{
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_ALBUM_OPER_ERR, "Invalid RDB store");
    int64_t outRowId(0);
    int32_t albumId = 0;
    ValuesBucket value = const_cast<ValuesBucket &>(values);
    ValueObject valueObject;
    if (value.GetObject(SMARTALBUM_DB_ID, valueObject)) {
            valueObject.GetInt(albumId);
        }
    int32_t insertResult = rdbStore->Insert(outRowId, SMARTALBUM_TABLE, values);
    CHECK_AND_RETURN_RET_LOG(insertResult == NativeRdb::E_OK, E_ALBUM_OPER_ERR, "Insert failed");
    return outRowId;
}
int64_t MediaLibrarySmartAlbumDb::InsertCategorySmartAlbumInfo(const ValuesBucket &values,
    const shared_ptr<RdbStore> &rdbStore)
{
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_ALBUM_OPER_ERR, "Invalid RDB store");
    int64_t outRowId(0);
    int32_t albumId = 0;
    ValuesBucket value = const_cast<ValuesBucket &>(values);
    ValueObject valueObject;
    if (value.GetObject(SMARTALBUM_DB_ID, valueObject)) {
            valueObject.GetInt(albumId);
        }
    int32_t insertResult = rdbStore->Insert(outRowId, CATEGORY_SMARTALBUM_MAP_TABLE, values);
    CHECK_AND_RETURN_RET_LOG(insertResult == NativeRdb::E_OK, E_ALBUM_OPER_ERR, "Insert failed");
    return outRowId;
}
int32_t MediaLibrarySmartAlbumDb::DeleteSmartAlbumInfo(const int32_t albumId, const shared_ptr<RdbStore> &rdbStore)
{
    CHECK_AND_RETURN_RET_LOG((rdbStore != nullptr) && (albumId > 0), E_ALBUM_OPER_ERR, "Invalid input");
    int32_t deletedRows(E_ALBUM_OPER_ERR);
    vector<string> whereArgs = { std::to_string(albumId)};
    int32_t deleteResult = rdbStore->Delete(deletedRows, SMARTALBUM_TABLE, SMARTALBUM_DB_COND, whereArgs);
    CHECK_AND_RETURN_RET_LOG(deleteResult == NativeRdb::E_OK, E_ALBUM_OPER_ERR, "Delete failed");
    return (deletedRows > 0) ? E_SUCCESS : E_FAIL;
}
}  // namespace Media
}  // namespace OHOS

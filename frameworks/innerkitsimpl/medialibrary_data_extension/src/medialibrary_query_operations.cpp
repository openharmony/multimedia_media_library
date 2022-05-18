/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "medialibrary_query_operations.h"
#include "medialibrary_query_db.h"
#include "media_log.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
shared_ptr<AbsSharedResultSet> MediaLibraryQueryOperations::QueryMediaVolumeInfoUtil(
    const shared_ptr<RdbStore> &rdbStore, const MediaLibraryQueryDb &queryDb)
{
    shared_ptr<AbsSharedResultSet> querySet = const_cast<MediaLibraryQueryDb &>(queryDb).QuerySql(QUERY_MEDIA_VOLUME,
        rdbStore);
    MEDIA_ERR_LOG("QUERY_MEDIA_VOLUME = %{public}s", QUERY_MEDIA_VOLUME.c_str());
    return querySet;
}

shared_ptr<AbsSharedResultSet> MediaLibraryQueryOperations::HandleMediaVolume(
    const shared_ptr<RdbStore> &rdbStore, const MediaLibraryQueryDb &queryDb)
{
    shared_ptr<AbsSharedResultSet> querySet;
    if (rdbStore != nullptr) {
        querySet = QueryMediaVolumeInfoUtil(rdbStore, queryDb);
    }
    return querySet;
}

shared_ptr<AbsSharedResultSet> MediaLibraryQueryOperations::HandleQueryOperations(
    const string &oprn, const QueryData &queryData, const shared_ptr<RdbStore> &rdbStore)
{
    MEDIA_ERR_LOG("HandleSmartAlbumOperations");
    MediaLibraryQueryDb queryDb;
    shared_ptr<AbsSharedResultSet> querySet;
    ValueObject valueObject;
    if (oprn == MEDIA_QUERYOPRN_QUERYVOLUME) {
        querySet = HandleMediaVolume(rdbStore, queryDb);
    }
    return querySet;
}
} // namespace Media
} // namespace OHOS

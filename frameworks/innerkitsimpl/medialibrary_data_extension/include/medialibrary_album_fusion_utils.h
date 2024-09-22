/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIALIBRARY_ALBUM_FUSION_UTILS_H
#define OHOS_MEDIALIBRARY_ALBUM_FUSION_UTILS_H

#include <vector>

#include "media_column.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_album_compatibility_fusion_sql.h"
#include "medialibrary_errno.h"
#include "photo_map_column.h"
#include "source_album.h"
#include "medialibrary_rdb_transaction.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_unistore.h"
#include "medialibrary_unistore_manager.h"

namespace OHOS {
namespace Media {
class MediaLibraryAlbumFusionUtils {
public:
    EXPORT static int32_t RemoveMisAddedHiddenData(NativeRdb::RdbStore *upgradeStore);
    EXPORT static int32_t HandleMatchedDataFusion(NativeRdb::RdbStore *upgradeStore);
    EXPORT static int32_t HandleNotMatchedDataFusion(NativeRdb::RdbStore *upgradeStore);
    EXPORT static int32_t HandleNotMatchedDataMigration(NativeRdb::RdbStore *upgradeStore,
        std::multimap<int32_t, std::vector<int32_t>> &notMatchedMap);
    EXPORT static int32_t HandleSingleFileCopy(NativeRdb::RdbStore *upgradeStore, const int32_t &assetId,
        const int32_t &ownerAlbumId, int64_t &newAssetId);
    EXPORT static int32_t RebuildAlbumAndFillCloudValue(NativeRdb::RdbStore *upgradeStore);
    EXPORT static int32_t HandleChangeNameAlbum(NativeRdb::RdbStore *upgradeStore);
    EXPORT static int32_t CompensateLpathForLocalAlbum(NativeRdb::RdbStore *upgradeStore);
    EXPORT static int32_t MergeClashSourceAlbum(NativeRdb::RdbStore *upgradeStore,
        std::shared_ptr<NativeRdb::ResultSet> &resultSet, const int32_t &sourceAlbumId, const int64_t &targetAlbumId);
    EXPORT static void SetParameterToStopSync();
    EXPORT static void SetParameterToStartSync();
    EXPORT static int32_t CleanInvalidCloudAlbumAndData();
    EXPORT static int32_t CopyLocalSingleFile(NativeRdb::RdbStore *upgradeStore, const int32_t &assetId,
        const int32_t &ownerAlbumId, std::shared_ptr<NativeRdb::ResultSet> &resultSet, int64_t &newAssetId);
    EXPORT static int32_t CopyCloudSingleFile(NativeRdb::RdbStore *upgradeStore, const int32_t &assetId,
        const int32_t &ownerAlbumId, std::shared_ptr<NativeRdb::ResultSet> &resultSet, int64_t &newAssetId);
    EXPORT static int32_t DeleteALbumAndUpdateRelationship(NativeRdb::RdbStore *upgradeStore,
        const int32_t &oldAlbumId, const int64_t &newAlbumId, bool isCloudAblum);
    EXPORT static bool IsCloudAlbum(std::shared_ptr<NativeRdb::ResultSet> resultSet);
    EXPORT static void BuildAlbumInsertValuesSetName(NativeRdb::RdbStore *upgradeStore,
        NativeRdb::ValuesBucket &values, std::shared_ptr<NativeRdb::ResultSet> &resultSet,
        const std::string &newAlbumName);
    EXPORT static int32_t RefreshAllAlbums();
private:
    static int32_t HandleFirstData(NativeRdb::RdbStore *upgradeStore,
        const int32_t &assetId, const int32_t &ownerAlbumId);
    static int32_t HandleRestData(NativeRdb::RdbStore *upgradeStore, const int32_t &assetId,
        const std::vector<int32_t> &restOwnerAlbumIds, int32_t &handledCount);
    static int32_t HandleNoOwnerData(NativeRdb::RdbStore *upgradeStore);
    static int32_t HandleExpiredAlbumData(NativeRdb::RdbStore *upgradeStore);
    static int32_t QueryNoMatchedMap(NativeRdb::RdbStore *upgradeStore,
        std::multimap<int32_t, std::vector<int32_t>> &notMatchedMap, bool isUpgrade);
    static int32_t HandleNewCloudDirtyData(NativeRdb::RdbStore *upgradeStore,
        std::multimap<int32_t, std::vector<int32_t>> &notMatchedMap);
    static int32_t HandleDuplicateAlbum(NativeRdb::RdbStore *upgradeStore);
    static int32_t HandleMisMatchScreenRecord(NativeRdb::RdbStore *upgradeStore);
};
}
}
#endif // OHOS_MEDIALIBRARY_ALBUM_FUSION_UTILS_H
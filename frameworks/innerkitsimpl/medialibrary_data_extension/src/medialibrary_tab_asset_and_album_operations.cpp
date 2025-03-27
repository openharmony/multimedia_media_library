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

#include "medialibrary_tab_asset_and_album_operations.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_unistore_manager.h"

using namespace OHOS::DataShare;
using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
std::shared_ptr<NativeRdb::ResultSet> MediaLibraryTableAssetAlbumOperations::Query(
    const NativeRdb::RdbPredicates &rdbPredicate, const std::vector<std::string> &columns)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbstore is nullptr");
        return nullptr;
    }

    return rdbStore->QueryWithFilter(rdbPredicate, columns);
}

int32_t MediaLibraryTableAssetAlbumOperations::Delete(NativeRdb::RdbPredicates &rdbPredicate)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbstore is nullptr");
        return E_HAS_DB_ERROR;
    }

    return rdbStore->Delete(rdbPredicate);
}

int32_t MediaLibraryTableAssetAlbumOperations::OprnTableOversizeChecker(void)
{
    static int64_t lastcheckTime {0};
    if ((MediaFileUtils::UTCTimeMilliSeconds() - lastcheckTime) >= OPRN_TABLE_OVERSIZE_CHECK_INTERVAL) {
        MEDIA_INFO_LOG("operation table oversize check");
        auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
        if (rdbStore == nullptr) {
            MEDIA_ERR_LOG("rdbstore is nullptr");
            return E_HAS_DB_ERROR;
        }
        NativeRdb::RdbPredicates predicates(OPRN_TABLE_NAME);
        std::vector<std::string> columns;

        auto resultSet = rdbStore->QueryWithFilter(predicates, columns);
        int rowCount = 0;
        auto ret = resultSet->GetRowCount(rowCount);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("rdb failed");
            return E_HAS_DB_ERROR;
        }
        if (rowCount > OPRN_TABLE_OVERSIZE_LIMIT) {
            int ret = rdbStore->ExecuteSql(DELETE_FROM_OPERATION_TABLE);
            if (ret != NativeRdb::E_OK) {
                MEDIA_ERR_LOG("Query not match data fails");
                return E_HAS_DB_ERROR;
            }
            MEDIA_INFO_LOG("oprn table aging delete");
        }
        lastcheckTime = MediaFileUtils::UTCTimeMilliSeconds();
    }
    return E_OK;
}
} // namespace Media
} // namespace OHOS
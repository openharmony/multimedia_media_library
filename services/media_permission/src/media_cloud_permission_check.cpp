/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#define MLOG_TAG "MediaPermissionCheck"

#include "media_cloud_permission_check.h"

#include <string>

#include "media_app_uri_permission_column.h"
#include "media_log.h"
#include "permission_utils.h"
#include "result_set_utils.h"

using namespace std;

namespace OHOS::Media {
int32_t CloudReadPermissionCheck::CheckPermission(uint32_t businessCode, const PermissionHeaderReq &data)
{
    MEDIA_DEBUG_LOG("CloudReadPermissionCheck enter, API code=%{public}d", businessCode);
    CHECK_AND_RETURN_RET_LOG(PermissionUtils::CheckCallerPermission(CLOUD_READ_ALL_PHOTO_PERMISSION),
        E_PERMISSION_DENIED, "CloudReadAllPhoto permission denied!");
    return E_SUCCESS;
}

int32_t CloudReadPermissionCheck::CheckPureCloudAssets(const std::string &fileId)
{
    CHECK_AND_RETURN_RET(!PermissionUtils::CheckCloudPermission(), E_SUCCESS);
    NativeRdb::RdbPredicates rdbPredicate(PhotoColumn::PHOTOS_TABLE);
    rdbPredicate.EqualTo(MediaColumn::MEDIA_ID, fileId);
    vector<string> columns{PhotoColumn::PHOTO_POSITION};
    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicate, columns);
    CHECK_AND_RETURN_RET_LOG(
        TryToGoToFirstRow(resultSet), E_INVALID_VALUES, "Query fileId: %{public}s failed", fileId.c_str());
    int32_t position = GetInt32Val(PhotoColumn::PHOTO_POSITION, resultSet);
    CHECK_AND_RETURN_RET_LOG(position != static_cast<int32_t>(PhotoPositionType::CLOUD),
        E_PERMISSION_DENIED,
        "No READ_CLOUD_IMAGEVIDEO permission, Cannot access pure cloud asset: %{public}s",
        fileId.c_str());
    return E_SUCCESS;
}

void CloudReadPermissionCheck::AddCloudAssetFilter(NativeRdb::RdbPredicates &predicates)
{
    if (PermissionUtils::CheckCloudPermission()) {
        return;
    }

    string condition = predicates.GetWhereClause();
    int64_t tokenId = static_cast<int64_t>(IPCSkeleton::GetCallingFullTokenID());
    const string clause = " (" + PhotoColumn::PHOTO_POSITION + " IN (1, 3) OR EXISTS (SELECT 1 FROM " +
                          AppUriPermissionColumn::APP_URI_PERMISSION_TABLE + " WHERE " +
                          AppUriPermissionColumn::APP_URI_PERMISSION_TABLE + "." + AppUriPermissionColumn::FILE_ID +
                          " = " + PhotoColumn::PHOTOS_TABLE + "." + MediaColumn::MEDIA_ID + " AND " +
                          AppUriPermissionColumn::APP_URI_PERMISSION_TABLE + "." +
                          AppUriPermissionColumn::TARGET_TOKENID + " = " + to_string(tokenId) + " AND " +
                          AppUriPermissionColumn::APP_URI_PERMISSION_TABLE + "." +
                          AppUriPermissionColumn::PERMISSION_TYPE + " IN (0, 1, 2, 3, 4)))";
    condition = condition.empty() ? clause : " (" + condition + ") AND " + clause;
    predicates.SetWhereClause(condition);

    MEDIA_WARN_LOG("No READ_CLOUD_IMAGEVIDEO permission, filter pure cloud assets");
}

int32_t CloudWritePermissionCheck::CheckPermission(uint32_t businessCode, const PermissionHeaderReq &data)
{
    MEDIA_DEBUG_LOG("CloudWritePermissionCheck enter, API code=%{public}d", businessCode);
    CHECK_AND_RETURN_RET_LOG(PermissionUtils::CheckCallerPermission(CLOUD_WRITE_ALL_PHOTO_PERMISSION),
        E_PERMISSION_DENIED, "CloudWriteAllPhoto permission denied!");
    return E_SUCCESS;
}
} // namespace OHOS::Media

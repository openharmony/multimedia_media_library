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

#define MLOG_TAG "DbPermissionHandler"

#include "db_permission_handler.h"

#include <cstdlib>

#include "media_file_uri.h"
#include "media_file_utils.h"
#include "medialibrary_bundle_manager.h"
#include "medialibrary_rdbstore.h"
#include "rdb_utils.h"
#include "medialibrary_uripermission_operations.h"
#include "permission_utils.h"

using namespace std;
using namespace OHOS::RdbDataShareAdapter;

namespace OHOS::Media {
static set<int> readPermSet{0, 1, 3, 4};

static set<int> writePermSet{2, 3, 4};

int32_t DbPermissionHandler::ExecuteCheckPermission(MediaLibraryCommand &cmd, PermParam &permParam)
{
    MEDIA_DEBUG_LOG("DbPermissionHandler enter");
    bool isWrite = permParam.isWrite;
    string appId = GetClientAppId();
    string fileId = MediaFileUtils::GetIdFromUri(cmd.GetUri().ToString());
    MediaType mediaType = MediaFileUri::GetMediaTypeFromUri(cmd.GetUri().ToString());
    MEDIA_DEBUG_LOG("isWrite=%{public}d,appId=%{public}s,fileId=%{public}s,mediaType=%{public}d",
        isWrite, appId.c_str(), fileId.c_str(), mediaType);
    if (appId.empty() || fileId.empty()) {
        MEDIA_ERR_LOG("invalid input");
        return E_INVALID_FILEID;
    }
    DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause("file_id = ? and appid = ? and uri_type = ?");
    predicates.SetWhereArgs({fileId, appId, to_string(mediaType)});
    vector<string> columns;
    auto queryResultSet = MediaLibraryRdbStore::Query(RdbUtils::ToPredicates(predicates, TABLE_PERMISSION), columns);
    CHECK_AND_RETURN_RET_LOG(queryResultSet != nullptr, E_PERMISSION_DENIED, "queryResultSet is nullptr");
    int count = 0;
    auto ret = queryResultSet->GetRowCount(count);
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK && count > 0, E_PERMISSION_DENIED, "db is no permission record");
    ret = queryResultSet->GoToFirstRow();
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, E_PERMISSION_DENIED, "GoToFirstRow fail");
    int index = -1;
    ret = queryResultSet->GetColumnIndex(FIELD_PERMISSION_TYPE, index);
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, E_PERMISSION_DENIED, "GetColumnIndex fail");
    int32_t permissionType = 0;
    ret = queryResultSet->GetInt(index, permissionType);
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, E_PERMISSION_DENIED, "GetInt fail");
    if (!isWrite) {
        return ConvertPermResult(readPermSet.count(permissionType));
    }
    return ConvertPermResult(writePermSet.count(permissionType));
}

} // namespace name
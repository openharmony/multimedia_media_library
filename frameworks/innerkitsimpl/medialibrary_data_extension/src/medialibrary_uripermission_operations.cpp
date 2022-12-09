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

#include "medialibrary_uripermission_operations.h"

#include "common_func.h"
#include "ipc_skeleton.h"
#include "medialibrary_errno.h"
#include "medialibrary_object_utils.h"
#include "media_log.h"
#include "permission_utils.h"

using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;

namespace OHOS {
namespace Media {

static bool CheckMode(const string& mode)
{
    if (mode != MEDIA_FILEMODE_READONLY) {
        MEDIA_ERR_LOG("mode format is error: %{public}s", mode.c_str());
        return false;
    }
    return true;
}

int32_t UriPermissionOperations::HandleUriPermOperations(MediaLibraryCommand &cmd)
{
    string bundleName;
    bool isSystemApp = false;
    PermissionUtils::GetClientBundle(IPCSkeleton::GetCallingUid(), bundleName, isSystemApp);
    if (!isSystemApp) {
        MEDIA_ERR_LOG("the caller is not system app");
        return E_PERMISSION_DENIED;
    }

    int32_t errCode = E_FAIL;
    switch (cmd.GetOprnType()) {
        case OperationType::INSERT_PERMISSION:
            errCode = HandleUriPermInsert(cmd);
            break;
        default:
            MEDIA_ERR_LOG("unknown operation type %{public}d", cmd.GetOprnType());
            break;
    }
    return errCode;
}

int32_t UriPermissionOperations::IsUriPermissionExists(const string &fileId, const string &bundleName,
    const string &mode)
{
    MediaLibraryCommand cmd(Uri(MEDIALIBRARY_BUNDLEPERM_URI), OperationType::QUERY);
    cmd.GetAbsRdbPredicates()->EqualTo(PERMISSION_FILE_ID, fileId);
    cmd.GetAbsRdbPredicates()->And()->EqualTo(PERMISSION_BUNDLE_NAME, bundleName);
    cmd.GetAbsRdbPredicates()->And()->EqualTo(PERMISSION_MODE, mode);
    auto queryResult = MediaLibraryObjectUtils::QueryWithCondition(cmd, {}, "");
    CHECK_AND_RETURN_RET_LOG(queryResult != nullptr, E_HAS_DB_ERROR, "Failed to obtain value from database");
    int32_t count = -1;
    auto ret = queryResult->GetRowCount(count);
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, E_HAS_DB_ERROR, "Failed to obtain value from database");
    if (count <= 0) {
        return E_PERMISSION_DENIED;
    }
    return E_OK;
}

int32_t UriPermissionOperations::HandleUriPermInsert(MediaLibraryCommand &cmd)
{
    ValuesBucket valuesBucket = cmd.GetValueBucket();
    int32_t fileId = -1;
    ValueObject valueObject;
    if (valuesBucket.GetObject(PERMISSION_FILE_ID, valueObject)) {
        valueObject.GetInt(fileId);
    } else {
        MEDIA_ERR_LOG("ValueBucket does not have PERMISSION_FILE_ID");
        return E_INVALID_VALUES;
    }

    string bundleName;
    if (valuesBucket.GetObject(PERMISSION_BUNDLE_NAME, valueObject)) {
        valueObject.GetString(bundleName);
    } else {
        MEDIA_ERR_LOG("ValueBucket does not have PERMISSION_BUNDLE_NAME");
        return E_INVALID_VALUES;
    }

    string mode;
    if (valuesBucket.GetObject(PERMISSION_MODE, valueObject)) {
        valueObject.GetString(mode);
    } else {
        MEDIA_ERR_LOG("ValueBucket does not have PERMISSION_MODE");
        return E_INVALID_VALUES;
    }
    if (!CheckMode(mode)) {
        return E_INVALID_MODE;
    }

    if (IsUriPermissionExists(to_string(fileId), bundleName, mode) == E_OK) {
        return E_OK;
    }

    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return E_HAS_DB_ERROR;
    }

    int64_t outRowId = -1;
    int32_t errCode = uniStore->Insert(cmd, outRowId);
    return (errCode == NativeRdb::E_OK) ? outRowId : errCode;
}

// you can only set mode "r"
int32_t UriPermissionOperations::CheckUriPermission(const std::string &fileUri, const std::string &mode)
{
    if (!CheckMode(mode)) {
        return E_INVALID_MODE;
    }
    string bundleName;
    bool isSystemApp = false;
    PermissionUtils::GetClientBundle(IPCSkeleton::GetCallingUid(), bundleName, isSystemApp);
    string fileId = MediaLibraryDataManagerUtils::GetIdFromUri(fileUri);
    return IsUriPermissionExists(fileId, bundleName, mode);
}
}   // Media
}   // OHOS
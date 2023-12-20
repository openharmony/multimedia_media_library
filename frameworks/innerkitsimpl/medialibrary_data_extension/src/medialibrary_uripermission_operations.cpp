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
#include "medialibrary_bundle_manager.h"
#include "medialibrary_errno.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_type_const.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "permission_utils.h"
#include "result_set_utils.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;

static bool CheckMode(string& mode)
{
    transform(mode.begin(), mode.end(), mode.begin(), ::tolower);
    if (MEDIA_OPEN_MODES.find(mode) == MEDIA_OPEN_MODES.end()) {
        MEDIA_ERR_LOG("mode format is error: %{private}s", mode.c_str());
        return false;
    }
    string tempMode;
    if (mode.find(MEDIA_FILEMODE_READONLY) != string::npos) {
        tempMode += MEDIA_FILEMODE_READONLY;
    }
    if (mode.find(MEDIA_FILEMODE_WRITEONLY) != string::npos) {
        tempMode += MEDIA_FILEMODE_WRITEONLY;
    }
    mode = tempMode;
    return true;
}

int32_t UriPermissionOperations::HandleUriPermOperations(MediaLibraryCommand &cmd)
{
    if (!PermissionUtils::CheckIsSystemAppByUid()) {
        MEDIA_ERR_LOG("the caller is not system app");
        return E_PERMISSION_DENIED;
    }
    string bundleName = MediaLibraryBundleManager::GetInstance()->GetClientBundleName();

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

int32_t UriPermissionOperations::GetUriPermissionMode(const string &fileId, const string &bundleName,
    int32_t tableType, string &mode)
{
    MediaLibraryCommand cmd(Uri(MEDIALIBRARY_BUNDLEPERM_URI), OperationType::QUERY);
    cmd.GetAbsRdbPredicates()->EqualTo(PERMISSION_FILE_ID, fileId);
    cmd.GetAbsRdbPredicates()->And()->EqualTo(PERMISSION_BUNDLE_NAME, bundleName);
    cmd.GetAbsRdbPredicates()->And()->EqualTo(PERMISSION_TABLE_TYPE, to_string(tableType));
    auto queryResult = MediaLibraryObjectUtils::QueryWithCondition(cmd, {}, "");
    CHECK_AND_RETURN_RET_LOG(queryResult != nullptr, E_HAS_DB_ERROR, "Failed to obtain value from database");
    int count = -1;
    CHECK_AND_RETURN_RET_LOG(queryResult->GetRowCount(count) == NativeRdb::E_OK, E_HAS_DB_ERROR,
        "Failed to get query result row count");
    if (count <= 0) {
        return E_PERMISSION_DENIED;
    }
    CHECK_AND_RETURN_RET_LOG(queryResult->GoToFirstRow() == NativeRdb::E_OK, E_HAS_DB_ERROR,
        "Failed to go to first row");
    mode = GetStringVal(PERMISSION_MODE, queryResult);
    return E_SUCCESS;
}

int32_t CheckUriPermValues(ValuesBucket &valuesBucket, int32_t &fileId, string &bundleName, int32_t &tableType,
    string &inputMode)
{
    ValueObject valueObject;
    if (valuesBucket.GetObject(PERMISSION_FILE_ID, valueObject)) {
        valueObject.GetInt(fileId);
    } else {
        MEDIA_ERR_LOG("ValueBucket does not have PERMISSION_FILE_ID");
        return E_INVALID_VALUES;
    }

    if (valuesBucket.GetObject(PERMISSION_BUNDLE_NAME, valueObject)) {
        valueObject.GetString(bundleName);
    } else {
        MEDIA_ERR_LOG("ValueBucket does not have PERMISSION_BUNDLE_NAME");
        return E_INVALID_VALUES;
    }

    if (valuesBucket.GetObject(PERMISSION_MODE, valueObject)) {
        valueObject.GetString(inputMode);
    } else {
        MEDIA_ERR_LOG("ValueBucket does not have PERMISSION_MODE");
        return E_INVALID_VALUES;
    }

    if (valuesBucket.GetObject(PERMISSION_TABLE_TYPE, valueObject)) {
        valueObject.GetInt(tableType);
    } else {
        MEDIA_ERR_LOG("ValueBucket does not have PERMISSION_TABLE_TYPE");
        return E_INVALID_VALUES;
    }
    if (!CheckMode(inputMode)) {
        return E_INVALID_MODE;
    }
    valuesBucket.Delete(PERMISSION_MODE);
    valuesBucket.PutString(PERMISSION_MODE, inputMode);
    return E_SUCCESS;
}

#ifdef MEDIALIBRARY_COMPATIBILITY
static void ConvertVirtualIdToRealId(ValuesBucket &valuesBucket, int32_t &fileId, int32_t tableType)
{
    if (tableType == static_cast<int32_t>(TableType::TYPE_PHOTOS)) {
        fileId = MediaFileUtils::GetRealIdByTable(fileId, PhotoColumn::PHOTOS_TABLE);
    } else if (tableType == static_cast<int32_t>(TableType::TYPE_AUDIOS)) {
        fileId = MediaFileUtils::GetRealIdByTable(fileId, AudioColumn::AUDIOS_TABLE);
    } else {
        fileId = MediaFileUtils::GetRealIdByTable(fileId, MEDIALIBRARY_TABLE);
    }

    valuesBucket.Delete(PERMISSION_FILE_ID);
    valuesBucket.PutInt(PERMISSION_FILE_ID, fileId);
}
#endif


int32_t UriPermissionOperations::HandleUriPermInsert(MediaLibraryCommand &cmd)
{
    int32_t fileId;
    string bundleName;
    string inputMode;
    int32_t tableType;
    ValuesBucket &valuesBucket = cmd.GetValueBucket();
    auto ret = CheckUriPermValues(valuesBucket, fileId, bundleName, tableType, inputMode);
    CHECK_AND_RETURN_RET(ret == E_SUCCESS, ret);

#ifdef MEDIALIBRARY_COMPATIBILITY
    if (cmd.GetApi() != MediaLibraryApi::API_10) {
        ConvertVirtualIdToRealId(valuesBucket, fileId, tableType);
    }
#endif

    string permissionMode;
    ret = GetUriPermissionMode(to_string(fileId), bundleName, tableType, permissionMode);
    if ((ret != E_SUCCESS) && (ret != E_PERMISSION_DENIED)) {
        return ret;
    }

    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(uniStore != nullptr, E_HAS_DB_ERROR, "uniStore is nullptr!");

    if (ret == E_PERMISSION_DENIED) {
        int64_t outRowId = -1;
        return uniStore->Insert(cmd, outRowId);
    }
    if (permissionMode.find(inputMode) != string::npos) {
        return E_SUCCESS;
    }
    ValuesBucket updateValues;
    updateValues.PutString(PERMISSION_MODE, MEDIA_FILEMODE_READWRITE);
    MediaLibraryCommand updateCmd(Uri(MEDIALIBRARY_BUNDLEPERM_URI), updateValues);
    updateCmd.GetAbsRdbPredicates()->EqualTo(PERMISSION_FILE_ID, to_string(fileId))->And()->
        EqualTo(PERMISSION_BUNDLE_NAME, bundleName);
    int32_t updatedRows = -1;
    return uniStore->Update(updateCmd, updatedRows);
}

static inline int32_t GetTableTypeFromTableName(const std::string &tableName)
{
    if (tableName == PhotoColumn::PHOTOS_TABLE) {
        return static_cast<int32_t>(TableType::TYPE_PHOTOS);
    } else if (tableName == AudioColumn::AUDIOS_TABLE) {
        return static_cast<int32_t>(TableType::TYPE_AUDIOS);
    } else {
        return static_cast<int32_t>(TableType::TYPE_FILES);
    }
}

int32_t UriPermissionOperations::InsertBundlePermission(const int32_t &fileId, const std::string &bundleName,
    const std::string &mode, const std::string &tableName)
{
    string curMode;
    int32_t tableType = GetTableTypeFromTableName(tableName);
    auto ret = GetUriPermissionMode(to_string(fileId), bundleName, tableType, curMode);
    if ((ret != E_SUCCESS) && (ret != E_PERMISSION_DENIED)) {
        return ret;
    }
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(uniStore != nullptr, E_HAS_DB_ERROR, "uniStore is nullptr!");
    if (ret == E_PERMISSION_DENIED) {
        ValuesBucket addValues;
        addValues.PutInt(PERMISSION_FILE_ID, fileId);
        addValues.PutString(PERMISSION_BUNDLE_NAME, bundleName);
        addValues.PutString(PERMISSION_MODE, mode);
        addValues.PutInt(PERMISSION_TABLE_TYPE, tableType);
        MediaLibraryCommand cmd(Uri(MEDIALIBRARY_BUNDLEPERM_URI), addValues);
        int64_t outRowId = -1;
        return uniStore->Insert(cmd, outRowId);
    }
    if (curMode.find(mode) != string::npos) {
        return E_SUCCESS;
    }
    ValuesBucket updateValues;
    updateValues.PutString(PERMISSION_MODE, mode);
    MediaLibraryCommand updateCmd(Uri(MEDIALIBRARY_BUNDLEPERM_URI), updateValues);
    updateCmd.GetAbsRdbPredicates()->EqualTo(PERMISSION_FILE_ID, to_string(fileId))->And()->
        EqualTo(PERMISSION_BUNDLE_NAME, bundleName)->And()->
        EqualTo(PERMISSION_TABLE_TYPE, to_string(tableType));
    int32_t updatedRows = -1;
    return uniStore->Update(updateCmd, updatedRows);
}

int32_t UriPermissionOperations::DeleteBundlePermission(const std::string &fileId, const std::string &bundleName,
    const std::string &tableName)
{
    int32_t tableType = GetTableTypeFromTableName(tableName);

    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(uniStore != nullptr, E_HAS_DB_ERROR, "uniStore is nullptr!");
    Uri uri(MEDIALIBRARY_BUNDLEPERM_URI);
    MediaLibraryCommand deleteCmd(uri);
    deleteCmd.GetAbsRdbPredicates()->EqualTo(PERMISSION_FILE_ID, fileId)->And()->
        EqualTo(PERMISSION_BUNDLE_NAME, bundleName)->And()->
        EqualTo(PERMISSION_TABLE_TYPE, to_string(tableType));
    int32_t deleteRows = -1;
    int32_t ret = uniStore->Delete(deleteCmd, deleteRows);
    if (deleteRows > 0 && ret == NativeRdb::E_OK) {
        MEDIA_DEBUG_LOG("DeleteBundlePermission success:fileId:%{private}s, bundleName:%{private}s, table:%{private}s",
            fileId.c_str(), bundleName.c_str(), tableName.c_str());
        return E_OK;
    }
    return E_HAS_DB_ERROR;
}

int32_t UriPermissionOperations::CheckUriPermission(const std::string &fileUri, std::string mode)
{
    if (!CheckMode(mode)) {
        return E_INVALID_MODE;
    }
    string bundleName = MediaLibraryBundleManager::GetInstance()->GetClientBundleName();
    string fileId = MediaFileUtils::GetIdFromUri(fileUri);
    TableType tableType = TableType::TYPE_FILES;
    static map<string, TableType> tableMap = {
        { MEDIALIBRARY_TYPE_IMAGE_URI, TableType::TYPE_PHOTOS },
        { MEDIALIBRARY_TYPE_VIDEO_URI, TableType::TYPE_PHOTOS },
        { MEDIALIBRARY_TYPE_AUDIO_URI, TableType::TYPE_AUDIOS },
        { MEDIALIBRARY_TYPE_FILE_URI, TableType::TYPE_FILES },
        { PhotoColumn::PHOTO_TYPE_URI, TableType::TYPE_PHOTOS },
        { AudioColumn::AUDIO_TYPE_URI, TableType::TYPE_AUDIOS }
    };
    for (const auto &iter : tableMap) {
        if (fileUri.find(iter.first) != string::npos) {
            tableType = iter.second;
        }
    }
    string permissionMode;
    int32_t ret = GetUriPermissionMode(fileId, bundleName, static_cast<int32_t>(tableType), permissionMode);
    CHECK_AND_RETURN_RET(ret == E_SUCCESS, ret);
    return (permissionMode.find(mode) != string::npos) ? E_SUCCESS : E_PERMISSION_DENIED;
}
}   // Media
}   // OHOS
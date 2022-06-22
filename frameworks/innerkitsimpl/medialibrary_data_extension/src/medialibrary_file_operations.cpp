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

#include "medialibrary_file_operations.h"

#include "datashare_predicates.h"
#include "datashare_result_set.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_dir_operations.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_smartalbum_map_db.h"
#include "rdb_utils.h"
#include "hitrace_meter.h"

using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::RdbDataShareAdapter;

namespace OHOS {
namespace Media {
MediaLibraryFileOperations::MediaLibraryFileOperations()
{
    uniStore_ = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
}

int32_t MediaLibraryFileOperations::HandleFileOperation(MediaLibraryCommand &cmd,
                                                        const unordered_map<string, DirAsset> &dirQuerySetMap)
{
    int32_t errCode = DATA_ABILITY_FAIL;
    auto values = cmd.GetValueBucket();
    string actualUri;

    ValueObject valueObject;
    if (values.GetObject(MEDIA_DATA_DB_URI, valueObject)) {
        valueObject.GetString(actualUri);
    }

    // only support CloseAsset when networkId is not empty
    string networkId = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(actualUri);
    if (!networkId.empty() && cmd.GetOprnType() != CLOSE) {
        return DATA_ABILITY_FAIL;
    }

    switch (cmd.GetOprnType()) {
        case CREATE:
            errCode = CreateFileOperation(cmd);
            break;
        case CLOSE:
            errCode = CloseFileOperation(cmd);
            break;
        case ISDICTIONARY:
            errCode = IsDirectoryOperation(cmd);
            break;
        case GETCAPACITY:
            errCode = GetAlbumCapacityOperation(cmd);
            break;
        default:
            MEDIA_WARNING_LOG("unknown operation type %{private}d", cmd.GetOprnType());
            break;
    }
    return errCode;
}

int32_t MediaLibraryFileOperations::CreateFileOperation(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    MediaLibraryObjectUtils objectUtils;
    return objectUtils.CreateFileObj(cmd);
}

int32_t MediaLibraryFileOperations::CloseFileOperation(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    MediaLibraryObjectUtils objectUtils;
    return objectUtils.CloseFile(cmd);
}

shared_ptr<AbsSharedResultSet> MediaLibraryFileOperations::QueryFavFiles(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    string strQueryCondition = MEDIA_DATA_DB_IS_FAV + " = 1 AND " + MEDIA_DATA_DB_MEDIA_TYPE + " <> 8";
    cmd.GetAbsRdbPredicates()->SetWhereClause(strQueryCondition);

    MediaLibraryObjectUtils objectUtils;
    return objectUtils.QueryFiles(cmd);
}

shared_ptr<AbsSharedResultSet> MediaLibraryFileOperations::QueryTrashFiles(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    string strQueryCondition = MEDIA_DATA_DB_DATE_TRASHED + " > 0 AND " + MEDIA_DATA_DB_MEDIA_TYPE + " <> 8";
    cmd.GetAbsRdbPredicates()->SetWhereClause(strQueryCondition);

    MediaLibraryObjectUtils objectUtils;
    return objectUtils.QueryFiles(cmd);
}

int32_t MediaLibraryFileOperations::GetAlbumCapacityOperation(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    int32_t errorCode = DATA_ABILITY_FAIL;
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;

    auto values = cmd.GetValueBucket();
    ValueObject valueObject;
    bool isFavourite = false;
    bool isTrash = false;
    if (values.GetObject(MEDIA_DATA_DB_IS_FAV, valueObject)) {
        valueObject.GetBool(isFavourite);
    }
    if (values.GetObject(MEDIA_DATA_DB_IS_TRASH, valueObject)) {
        valueObject.GetBool(isTrash);
    }

    if (isFavourite) {
        MEDIA_INFO_LOG("isFavourite");
        resultSet = QueryFavFiles(cmd);
    } else if (isTrash) {
        MEDIA_INFO_LOG("isTrash");
        resultSet = QueryTrashFiles(cmd);
    }

    if (resultSet != nullptr) {
        resultSet->GetRowCount(errorCode);
        MEDIA_INFO_LOG("GetRowCount %{private}d", errorCode);
    }

    return errorCode;
}

int32_t MediaLibraryFileOperations::ModifyFileOperation(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    int32_t errCode = DATA_ABILITY_FAIL;

    string strFileId = cmd.GetOprnFileId();
    if (strFileId == "-1") {
        MEDIA_ERR_LOG("Get id from uri or valuesBucket failed!");
        return errCode;
    }

    MediaLibraryObjectUtils objectUtils;
    string srcPath = objectUtils.GetPathByIdFromDb(strFileId);
    if (srcPath.empty()) {
        MEDIA_ERR_LOG("Get path of id %{private}s from database file!", strFileId.c_str());
        return errCode;
    }

    string dstFileName, dstReFilePath;
    auto values = cmd.GetValueBucket();
    ValueObject valueObject;
    if (values.GetObject(MEDIA_DATA_DB_NAME, valueObject)) {
        valueObject.GetString(dstFileName);
    }
    if (values.GetObject(MEDIA_DATA_DB_RELATIVE_PATH, valueObject)) {
        valueObject.GetString(dstReFilePath);
    }
    string dstFilePath = ROOT_MEDIA_DIR + dstReFilePath + dstFileName;

    return objectUtils.RenameFileObj(cmd, srcPath, dstFilePath);
}

int32_t MediaLibraryFileOperations::DeleteFileOperation(MediaLibraryCommand &cmd,
    const unordered_map<string, DirAsset> &dirQuerySetMap)
{
    int32_t errCode = DATA_ABILITY_FAIL;

    string strFileId = cmd.GetOprnFileId();
    if (strFileId == "-1") {
        MEDIA_ERR_LOG("Get id from uri or valuesBucket failed!");
        return errCode;
    }

    MediaLibraryObjectUtils objectUtils;
    string srcPath = objectUtils.GetPathByIdFromDb(strFileId);
    if (srcPath.empty()) {
        MEDIA_ERR_LOG("Get path of id %{private}s from database file!", strFileId.c_str());
        return errCode;
    }

    errCode = objectUtils.DeleteFileObj(cmd, srcPath);
    if (errCode > 0) {
        MediaLibraryDirOperations dirOprn;
        MediaLibrarySmartAlbumMapDb smartAlbumMapDbOprn;
        auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw();
        dirOprn.HandleDirOperations(MEDIA_DIROPRN_DELETEDIR, cmd.GetValueBucket(), rdbStore, dirQuerySetMap);
        smartAlbumMapDbOprn.DeleteAllAssetsMapInfo(std::stoi(strFileId), rdbStore);
    }
    return errCode;
}

int32_t MediaLibraryFileOperations::IsDirectoryOperation(MediaLibraryCommand &cmd)
{
    MEDIA_INFO_LOG("[lqh] enter");
    if (uniStore_ == nullptr) {
        MEDIA_ERR_LOG("uniStore_ is nullptr");
        return DATA_ABILITY_FAIL;
    }

    int32_t id = -1;
    ValueObject valueObject;
    auto values = cmd.GetValueBucket();
    if (values.GetObject(MEDIA_DATA_DB_ID, valueObject)) {
        valueObject.GetInt(id);
    }
    MEDIA_INFO_LOG("id = %{private}d", id);
    if (id == -1) {
        MEDIA_ERR_LOG("not dictionary id, can't do the judgement!");
        return DATA_ABILITY_FAIL;
    }

    cmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_ID, std::to_string(id));
    std::vector<std::string> columns;
    columns.push_back(MEDIA_DATA_DB_FILE_PATH);
    shared_ptr<AbsSharedResultSet> queryResultSet = uniStore_->Query(cmd, columns);
    string path = "";
    while (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t columnIndex;
        queryResultSet->GetColumnIndex(MEDIA_DATA_DB_FILE_PATH, columnIndex);
        queryResultSet->GetString(columnIndex, path);
        MEDIA_INFO_LOG("path = %{private}s", path.c_str());
    }
    if (MediaFileUtils::IsDirectory(path)) {
        MEDIA_INFO_LOG("%{private}s is a dictionary!", path.c_str());
        return DATA_ABILITY_SUCCESS;
    }
    MEDIA_INFO_LOG("%{private}s is NOT a dictionary!", path.c_str());
    return DATA_ABILITY_FAIL;
}

shared_ptr<AbsSharedResultSet> MediaLibraryFileOperations::QueryFileOperation(
    MediaLibraryCommand &cmd, vector<string> columns)
{
    shared_ptr<AbsSharedResultSet> queryResultSet;
    string strQueryCondition = cmd.GetAbsRdbPredicates()->GetWhereClause();
    if (strQueryCondition.empty()) {
        strQueryCondition = MEDIA_DATA_DB_ID + " = " + cmd.GetOprnFileId();
        cmd.GetAbsRdbPredicates()->SetWhereClause(strQueryCondition);
    }
    string networkId = cmd.GetOprnDevice();
    if (!networkId.empty()) {
        std::vector<string> devices;
        devices.push_back(networkId);
        cmd.GetAbsRdbPredicates()->InDevices(devices);
    }
    MEDIA_DEBUG_LOG("predicates.GetWhereClause() %{public}s", strQueryCondition.c_str());
    for (string whereArgs : cmd.GetAbsRdbPredicates()->GetWhereArgs()) {
        MEDIA_DEBUG_LOG("predicates.GetWhereArgs() %{public}s", whereArgs.c_str());
    }
    StartTrace(HITRACE_TAG_OHOS, "QueryFile RdbStore->Query");
    queryResultSet = uniStore_->Query(cmd, columns);
    FinishTrace(HITRACE_TAG_OHOS);
    int32_t count = -1;
    queryResultSet->GetRowCount(count);
    MEDIA_INFO_LOG("QueryFile count is %{public}d", count);
    return queryResultSet;
}
} // namespace Media
} // namespace OHOS

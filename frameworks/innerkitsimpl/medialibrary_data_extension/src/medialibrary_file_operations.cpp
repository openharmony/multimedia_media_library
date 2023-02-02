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
#define MLOG_TAG "FileOperation"

#include "medialibrary_file_operations.h"

#include "datashare_predicates.h"
#include "datashare_values_bucket.h"
#include "file_asset.h"
#include "hitrace_meter.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_db_const.h"
#include "medialibrary_dir_operations.h"
#include "medialibrary_errno.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_smartalbum_map_db.h"
#include "medialibrary_tracer.h"
#include "medialibrary_unistore_manager.h"
#include "native_album_asset.h"
#include "rdb_utils.h"

using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;
using namespace OHOS::RdbDataShareAdapter;

namespace OHOS {
namespace Media {
int32_t MediaLibraryFileOperations::HandleFileOperation(MediaLibraryCommand &cmd)
{
    int32_t errCode = E_FAIL;
    auto values = cmd.GetValueBucket();
    string actualUri;

    ValueObject valueObject;
    if (values.GetObject(MEDIA_DATA_DB_URI, valueObject)) {
        valueObject.GetString(actualUri);
    }

    // only support CloseAsset when networkId is not empty
    string networkId = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(actualUri);
    if (!networkId.empty() && cmd.GetOprnType() != OperationType::CLOSE) {
        return E_PERMISSION_DENIED;
    }

    switch (cmd.GetOprnType()) {
        case OperationType::CREATE:
            errCode = CreateFileOperation(cmd);
            break;
        case OperationType::CLOSE:
            errCode = CloseFileOperation(cmd);
            break;
        case OperationType::ISDICTIONARY:
            errCode = IsDirectoryOperation(cmd);
            break;
        case OperationType::GETCAPACITY:
            errCode = GetAlbumCapacityOperation(cmd);
            break;
        default:
            MEDIA_ERR_LOG("unknown operation type %{public}d", cmd.GetOprnType());
            break;
    }
    return errCode;
}

int32_t MediaLibraryFileOperations::CreateFileOperation(MediaLibraryCommand &cmd)
{
    MEDIA_DEBUG_LOG("enter");
    return MediaLibraryObjectUtils::CreateFileObj(cmd);
}

int32_t MediaLibraryFileOperations::CloseFileOperation(MediaLibraryCommand &cmd)
{
    MEDIA_DEBUG_LOG("enter");
    return MediaLibraryObjectUtils::CloseFile(cmd);
}

shared_ptr<AbsSharedResultSet> MediaLibraryFileOperations::QueryFavFiles(MediaLibraryCommand &cmd)
{
    MEDIA_DEBUG_LOG("enter");
    cmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_IS_FAV, "1");
    cmd.GetAbsRdbPredicates()->And()->NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, "8");

    return MediaLibraryObjectUtils::QueryWithCondition(cmd, {});
}

shared_ptr<AbsSharedResultSet> MediaLibraryFileOperations::QueryTrashFiles(MediaLibraryCommand &cmd)
{
    MEDIA_DEBUG_LOG("enter");
    cmd.GetAbsRdbPredicates()
        ->GreaterThan(MEDIA_DATA_DB_DATE_TRASHED, "0")
        ->And()
        ->NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, "8");

    return MediaLibraryObjectUtils::QueryWithCondition(cmd, {});
}

int32_t MediaLibraryFileOperations::GetAlbumCapacityOperation(MediaLibraryCommand &cmd)
{
    MEDIA_DEBUG_LOG("enter");
    int32_t errorCode = E_FAIL;
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
        resultSet = QueryFavFiles(cmd);
    } else if (isTrash) {
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
    MEDIA_DEBUG_LOG("enter");

    string strFileId = cmd.GetOprnFileId();
    if (strFileId.empty()) {
        MEDIA_ERR_LOG("MediaLibraryFileOperations::ModifyFileOperation Get id from uri or valuesBucket failed!");
        return E_INVALID_FILEID;
    }

    string srcPath = MediaLibraryObjectUtils::GetPathByIdFromDb(strFileId);
    if (srcPath.empty()) {
        MEDIA_ERR_LOG("MediaLibraryFileOperations::ModifyFileOperation Get path of id %{private}s from database file!",
            strFileId.c_str());
        return E_INVALID_FILEID;
    }

    string dstFileName;
    string dstReFilePath;
    auto values = cmd.GetValueBucket();
    ValueObject valueObject;
    if (values.GetObject(MEDIA_DATA_DB_NAME, valueObject)) {
        valueObject.GetString(dstFileName);
    }
    if (values.GetObject(MEDIA_DATA_DB_RELATIVE_PATH, valueObject)) {
        valueObject.GetString(dstReFilePath);
    }
    string dstFilePath = ROOT_MEDIA_DIR + dstReFilePath + dstFileName;

    if (srcPath.compare(dstFilePath) == 0) {
        return E_SAME_PATH;
    }

    return MediaLibraryObjectUtils::RenameFileObj(cmd, srcPath, dstFilePath);
}

int32_t MediaLibraryFileOperations::DeleteFileOperation(MediaLibraryCommand &cmd,
    const unordered_map<string, DirAsset> &dirQuerySetMap)
{
    string strFileId = cmd.GetOprnFileId();
    if (strFileId.empty()) {
        MEDIA_ERR_LOG("MediaLibraryFileOperations::DeleteFileOperation Get id from uri or valuesBucket failed!");
        return E_INVALID_FILEID;
    }

    string srcPath = MediaLibraryObjectUtils::GetPathByIdFromDb(strFileId);
    if (srcPath.empty()) {
        MEDIA_ERR_LOG("MediaLibraryFileOperations::DeleteFileOperation Get path of id %{private}s from database file!",
            strFileId.c_str());
        return E_INVALID_FILEID;
    }

    int32_t errCode = MediaLibraryObjectUtils::DeleteFileObj(cmd, srcPath);
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
    MEDIA_DEBUG_LOG("enter");
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr");
        return E_HAS_DB_ERROR;
    }

    string fileId = cmd.GetOprnFileId();
    if (fileId.empty()) {
        MEDIA_ERR_LOG("not dictionary id, can't do the judgement!");
        return E_INVALID_FILEID;
    }
    string path = MediaLibraryObjectUtils::GetPathByIdFromDb(fileId);
    if (MediaFileUtils::IsDirectory(path)) {
        MEDIA_INFO_LOG("%{private}s is a dictionary!", path.c_str());
        return E_SUCCESS;
    }
    MEDIA_INFO_LOG("%{private}s is NOT a dictionary!", path.c_str());
    return E_CHECK_DIR_FAIL;
}

shared_ptr<AbsSharedResultSet> MediaLibraryFileOperations::QueryFileOperation(
    MediaLibraryCommand &cmd, vector<string> columns)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr");
        return nullptr;
    }

    shared_ptr<AbsSharedResultSet> queryResultSet;
    string fileId = cmd.GetOprnFileId();
    if (cmd.GetAbsRdbPredicates()->GetWhereClause().empty() && !fileId.empty()) {
        cmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_ID, fileId);
    }
    string networkId = cmd.GetOprnDevice();
    if (!networkId.empty()) {
        std::vector<string> devices;
        devices.push_back(networkId);
        cmd.GetAbsRdbPredicates()->InDevices(devices);
    }
    MediaLibraryTracer tracer;
    tracer.Start("QueryFile RdbStore->Query");
    queryResultSet = uniStore->Query(cmd, columns);
    tracer.Finish();
    return queryResultSet;
}
} // namespace Media
} // namespace OHOS

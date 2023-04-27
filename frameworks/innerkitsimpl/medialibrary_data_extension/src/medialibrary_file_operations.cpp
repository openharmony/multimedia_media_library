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
#include "medialibrary_errno.h"
#include "medialibrary_notify.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_smartalbum_map_operations.h"
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
using ChangeType = AAFwk::ChangeInfo::ChangeType;

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
        case OperationType::COPY:
            errCode = CopyFileOperation(cmd);
            break;
        default:
            MEDIA_ERR_LOG("unknown operation type %{public}d", cmd.GetOprnType());
            break;
    }
    return errCode;
}

int32_t MediaLibraryFileOperations::CreateFileOperation(MediaLibraryCommand &cmd)
{
    return MediaLibraryObjectUtils::CreateFileObj(cmd);
}

int32_t MediaLibraryFileOperations::CloseFileOperation(MediaLibraryCommand &cmd)
{
    return MediaLibraryObjectUtils::CloseFile(cmd);
}

shared_ptr<NativeRdb::ResultSet> MediaLibraryFileOperations::QueryFavFiles(MediaLibraryCommand &cmd)
{
    cmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_IS_FAV, "1");
    cmd.GetAbsRdbPredicates()->And()->NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, std::to_string(MEDIA_TYPE_ALBUM));

    return MediaLibraryObjectUtils::QueryWithCondition(cmd, {});
}

shared_ptr<NativeRdb::ResultSet> MediaLibraryFileOperations::QueryTrashFiles(MediaLibraryCommand &cmd)
{
    cmd.GetAbsRdbPredicates()
        ->GreaterThan(MEDIA_DATA_DB_DATE_TRASHED, std::to_string(NOT_TRASHED))
        ->And()
        ->NotEqualTo(MEDIA_DATA_DB_MEDIA_TYPE, std::to_string(MEDIA_TYPE_ALBUM));

    return MediaLibraryObjectUtils::QueryWithCondition(cmd, {});
}

int32_t MediaLibraryFileOperations::GetAlbumCapacityOperation(MediaLibraryCommand &cmd)
{
    int32_t errorCode = E_FAIL;
    shared_ptr<NativeRdb::ResultSet> resultSet = nullptr;

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

int32_t MediaLibraryFileOperations::IsDirectoryOperation(MediaLibraryCommand &cmd)
{
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

constexpr bool START_PENDING = false;
static void SolvePendingInQuery(AbsRdbPredicates* predicates)
{
    string whereClause = predicates->GetWhereClause();
    size_t groupByPoint = whereClause.rfind("GROUP BY");
    string groupBy;
    if (groupByPoint != string::npos) {
        groupBy = whereClause.substr(groupByPoint);
        whereClause = whereClause.substr(0, groupByPoint);
    }

    predicates->SetWhereClause(whereClause);
    predicates->EqualTo(MEDIA_DATA_DB_TIME_PENDING, "0");
    if (!groupBy.empty()) {
        predicates->SetWhereClause(predicates->GetWhereClause() + groupBy);
    }
}

shared_ptr<NativeRdb::ResultSet> MediaLibraryFileOperations::QueryFileOperation(
    MediaLibraryCommand &cmd, vector<string> columns)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr");
        return nullptr;
    }

    string fileId = cmd.GetOprnFileId();
    if (cmd.GetAbsRdbPredicates()->GetWhereClause().empty() && !fileId.empty()) {
        cmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_ID, fileId);
    }

    if (START_PENDING) {
        SolvePendingInQuery(cmd.GetAbsRdbPredicates());
    }
    string networkId = cmd.GetOprnDevice();
    if (!networkId.empty()) {
        std::vector<string> devices;
        devices.push_back(networkId);
        cmd.GetAbsRdbPredicates()->InDevices(devices);
    }
    MediaLibraryTracer tracer;
    tracer.Start("QueryFile RdbStore->Query");
    return uniStore->Query(cmd, columns);
}

int32_t MediaLibraryFileOperations::CopyFileOperation(MediaLibraryCommand &cmd)
{
    auto values = cmd.GetValueBucket();
    auto assetId = cmd.GetOprnFileId();
    ValueObject valueObject;
    string relativePath;
    if (values.GetObject(MEDIA_DATA_DB_RELATIVE_PATH, valueObject)) {
        valueObject.GetString(relativePath);
    }
    Uri srcUri(MEDIALIBRARY_DATA_URI + "/" + assetId);
    string srcUriString = srcUri.ToString();
    shared_ptr<FileAsset> srcFileAsset = MediaLibraryObjectUtils::GetFileAssetFromUri(srcUriString);
    if (srcFileAsset == nullptr) {
        return E_INVALID_URI;
    }
    if (srcFileAsset->GetMediaType() == MEDIA_TYPE_ALBUM) {
        return MediaLibraryObjectUtils::CopyDir(srcFileAsset, relativePath);
    } else {
        return MediaLibraryObjectUtils::CopyAsset(srcFileAsset, relativePath);
    }
}
} // namespace Media
} // namespace OHOS

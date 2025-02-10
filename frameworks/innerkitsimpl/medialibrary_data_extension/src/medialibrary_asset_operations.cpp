/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "medialibrary_asset_operations.h"

#include <algorithm>
#include <dirent.h>
#include <memory>
#include <mutex>
#include <sstream>

#include "cloud_media_asset_manager.h"
#include "directory_ex.h"
#include "file_asset.h"
#include "media_app_uri_permission_column.h"
#include "media_column.h"
#include "media_exif.h"
#include "media_file_utils.h"
#include "media_file_uri.h"
#include "media_log.h"
#include "media_scanner_manager.h"
#include "media_unique_number_column.h"
#include "medialibrary_album_operations.h"
#include "medialibrary_async_worker.h"
#include "medialibrary_audio_operations.h"
#include "medialibrary_bundle_manager.h"
#include "medialibrary_command.h"
#include "medialibrary_common_utils.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_inotify.h"
#include "medialibrary_notify.h"
#include "medialibrary_photo_operations.h"
#include "medialibrary_rdb_transaction.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_tracer.h"
#include "medialibrary_type_const.h"
#include "medialibrary_unistore_manager.h"
#include "media_privacy_manager.h"
#include "mimetype_utils.h"
#include "multistages_capture_manager.h"
#include "enhancement_manager.h"
#include "permission_utils.h"
#include "rdb_errno.h"
#include "rdb_predicates.h"
#include "rdb_store.h"
#include "rdb_utils.h"
#include "result_set_utils.h"
#include "thumbnail_service.h"
#include "uri_permission_manager_client.h"
#include "userfile_manager_types.h"
#include "value_object.h"
#include "values_bucket.h"
#include "medialibrary_formmap_operations.h"
#include "medialibrary_vision_operations.h"
#include "dfx_manager.h"
#include "dfx_const.h"
#include "moving_photo_file_utils.h"
#include "dfx_utils.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
mutex g_uniqueNumberLock;

const string DEFAULT_IMAGE_NAME = "IMG_";
const string DEFAULT_VIDEO_NAME = "VID_";
const string DEFAULT_AUDIO_NAME = "AUD_";
constexpr int32_t NO_DESENSITIZE = 3;
const string PHOTO_ALBUM_URI_PREFIX = "file://media/PhotoAlbum/";

int32_t MediaLibraryAssetOperations::HandleInsertOperation(MediaLibraryCommand &cmd)
{
    int errCode = E_ERR;
    switch (cmd.GetOprnType()) {
        case OperationType::CREATE:
            errCode = CreateOperation(cmd);
            break;
        case OperationType::CLOSE:
            errCode = CloseOperation(cmd);
            break;
        case OperationType::COMMIT_EDIT:
            errCode = MediaLibraryPhotoOperations::CommitEditInsert(cmd);
            if (errCode == E_SUCCESS) {
                MediaLibraryVisionOperations::EditCommitOperation(cmd);
            }
            break;
        case OperationType::REVERT_EDIT:
            errCode = MediaLibraryPhotoOperations::RevertToOrigin(cmd);
            if (errCode == E_SUCCESS) {
                MediaLibraryVisionOperations::EditCommitOperation(cmd);
            }
            break;
        case OperationType::SUBMIT_CACHE:
            errCode = MediaLibraryPhotoOperations::SubmitCache(cmd);
            break;
        case OperationType::ADD_FILTERS:
            errCode = MediaLibraryPhotoOperations::AddFilters(cmd);
            break;
        case OperationType::SCAN_WITHOUT_ALBUM_UPDATE:
            errCode = MediaLibraryPhotoOperations::ScanFileWithoutAlbumUpdate(cmd);
            break;
        case OperationType::FINISH_REQUEST_PICTURE:
            errCode = MediaLibraryPhotoOperations::FinishRequestPicture(cmd);
            break;
        case OperationType::CLONE_ASSET:
            errCode = MediaLibraryPhotoOperations::CloneSingleAsset(cmd);
            break;
        default:
            MEDIA_ERR_LOG("unknown operation type %{public}d", cmd.GetOprnType());
            break;
    }
    return errCode;
}

int32_t MediaLibraryAssetOperations::CreateOperation(MediaLibraryCommand &cmd)
{
    // CreateAsset specify type
    switch (cmd.GetOprnObject()) {
        case OperationObject::FILESYSTEM_PHOTO:
        case OperationObject::PTP_OPERATION:
            return MediaLibraryPhotoOperations::Create(cmd);
        case OperationObject::FILESYSTEM_AUDIO:
            return MediaLibraryAudioOperations::Create(cmd);
        case OperationObject::FILESYSTEM_ASSET:
            MEDIA_ERR_LOG("create asset by FileSysetm_Asset is deperated");
            return E_INVALID_VALUES;
        default:
            MEDIA_ERR_LOG("error operation object: %{public}d", cmd.GetOprnObject());
            return E_INVALID_VALUES;
    }
}

int32_t MediaLibraryAssetOperations::DeleteOperation(MediaLibraryCommand &cmd)
{
    // delete Asset specify type
    switch (cmd.GetOprnObject()) {
        case OperationObject::FILESYSTEM_PHOTO:
            return MediaLibraryPhotoOperations::Delete(cmd);
        case OperationObject::FILESYSTEM_AUDIO:
            return MediaLibraryAudioOperations::Delete(cmd);
        case OperationObject::FILESYSTEM_ASSET:
            MEDIA_ERR_LOG("delete asset by FILESYSTEM_ASSET is deperated");
            return E_INVALID_VALUES;
        default:
            MEDIA_ERR_LOG("error operation object: %{public}d", cmd.GetOprnObject());
            return E_INVALID_VALUES;
    }
}

shared_ptr<NativeRdb::ResultSet> MediaLibraryAssetOperations::QueryOperation(
    MediaLibraryCommand &cmd, const vector<string> &columns)
{
    // query asset specify type
    switch (cmd.GetOprnObject()) {
        case OperationObject::FILESYSTEM_PHOTO:
            return MediaLibraryPhotoOperations::Query(cmd, columns);
        case OperationObject::FILESYSTEM_AUDIO:
            return MediaLibraryAudioOperations::Query(cmd, columns);
        case OperationObject::FILESYSTEM_ASSET:
            MEDIA_ERR_LOG("api9 operation is not finished");
            return nullptr;
        case OperationObject::PAH_MOVING_PHOTO:
            return MediaLibraryPhotoOperations::ScanMovingPhoto(cmd, columns);
        default:
            MEDIA_ERR_LOG("error operation objec: %{public}d", cmd.GetOprnObject());
            return nullptr;
    }
}

int32_t MediaLibraryAssetOperations::UpdateOperation(MediaLibraryCommand &cmd)
{
    if (!AssetInputParamVerification::CheckParamForUpdate(cmd)) {
        return E_INVALID_VALUES;
    }

    switch (cmd.GetOprnObject()) {
        case OperationObject::PAH_PHOTO:
        case OperationObject::PAH_VIDEO:
        case OperationObject::FILESYSTEM_PHOTO:
        case OperationObject::PTP_OPERATION:
            return MediaLibraryPhotoOperations::Update(cmd);
        case OperationObject::FILESYSTEM_AUDIO:
            return MediaLibraryAudioOperations::Update(cmd);
        case OperationObject::FILESYSTEM_ASSET:
            MEDIA_ERR_LOG("create asset by FILESYSTEM_ASSET is deperated");
            return E_INVALID_VALUES;
        default:
            MEDIA_ERR_LOG("error operation object: %{public}d", cmd.GetOprnObject());
            return E_INVALID_VALUES;
    }
}

int32_t MediaLibraryAssetOperations::OpenOperation(MediaLibraryCommand &cmd, const string &mode)
{
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryAssetOperations::OpenOperation");

    // Open specify type
    switch (cmd.GetOprnObject()) {
        case OperationObject::FILESYSTEM_PHOTO:
        case OperationObject::PTP_OPERATION:
            return MediaLibraryPhotoOperations::Open(cmd, mode);
        case OperationObject::FILESYSTEM_AUDIO:
            return MediaLibraryAudioOperations::Open(cmd, mode);
        case OperationObject::HIGHLIGHT_COVER:
            return MediaLibraryAssetOperations::OpenHighlightCover(cmd, mode);
        case OperationObject::HIGHLIGHT_URI:
            return MediaLibraryAssetOperations::OpenHighlightVideo(cmd, mode);
        case OperationObject::FILESYSTEM_ASSET:
            MEDIA_ERR_LOG("open by FILESYSTEM_ASSET is deperated");
            return E_INVALID_VALUES;
        default:
            MEDIA_ERR_LOG("error operation object: %{public}d", cmd.GetOprnObject());
            return E_INVALID_VALUES;
    }
}

int32_t MediaLibraryAssetOperations::CloseOperation(MediaLibraryCommand &cmd)
{
    // Close specify type
    switch (cmd.GetOprnObject()) {
        case OperationObject::FILESYSTEM_PHOTO:
        case OperationObject::PTP_OPERATION:
            return MediaLibraryPhotoOperations::Close(cmd);
        case OperationObject::FILESYSTEM_AUDIO:
            return MediaLibraryAudioOperations::Close(cmd);
        case OperationObject::FILESYSTEM_ASSET:
            MEDIA_ERR_LOG("close by FILESYSTEM_ASSET is deperated");
            return E_INVALID_VALUES;
        default:
            MEDIA_ERR_LOG("error operation object: %{public}d", cmd.GetOprnObject());
            return E_INVALID_VALUES;
    }
}

static int32_t DropAllTables(const shared_ptr<MediaLibraryRdbStore> rdbStore)
{
    string dropSqlRowName = "drop_table_and_view_sql";
    string queryDropSql =
        "SELECT 'DROP ' || type || ' IF EXISTS ' || name || ';' as " + dropSqlRowName +
        " FROM sqlite_master" +
        " WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%';";
    auto dropSqlsResultSet = rdbStore->QuerySql(queryDropSql);
    if (dropSqlsResultSet == nullptr) {
        MEDIA_ERR_LOG("query Drop Sql failed");
        return E_HAS_DB_ERROR;
    }
    vector<string> dropSqlsVec;
    while (dropSqlsResultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t columnIndex = 0;
        if (dropSqlsResultSet->GetColumnIndex(dropSqlRowName, columnIndex) != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Get drop_table_and_view_sql column failed");
            return E_HAS_DB_ERROR;
        }
        string sql;
        if (dropSqlsResultSet->GetString(columnIndex, sql) != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Get drop_table_and_view_sql sql failed");
            return E_HAS_DB_ERROR;
        }
        if (!sql.empty()) {
            dropSqlsVec.push_back(sql);
        }
    }

    for (const auto &dropSql : dropSqlsVec) {
        rdbStore->ExecuteSql(dropSql);
    }
    return E_OK;
}

int32_t MediaLibraryAssetOperations::DeleteToolOperation(MediaLibraryCommand &cmd)
{
    auto valuesBucket = cmd.GetValueBucket();
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("Can not get rdb store");
        return E_HAS_DB_ERROR;
    }

    int32_t errCode = DropAllTables(rdbStore);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("Drop table failed, errCode=%{public}d", errCode);
        return errCode;
    }
    errCode = rdbStore->DataCallBackOnCreate();
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("DataCallBackOnCreate failed, errCode=%{public}d", errCode);
        return errCode;
    }
    MediaLibraryRdbStore::ResetAnalysisTables();
    MediaLibraryRdbStore::ResetSearchTables();
    const static vector<string> DELETE_DIR_LIST = {
        ROOT_MEDIA_DIR + PHOTO_BUCKET,
        ROOT_MEDIA_DIR + AUDIO_BUCKET,
        ROOT_MEDIA_DIR + CAMERA_DIR_VALUES,
        ROOT_MEDIA_DIR + VIDEO_DIR_VALUES,
        ROOT_MEDIA_DIR + PIC_DIR_VALUES,
        ROOT_MEDIA_DIR + AUDIO_DIR_VALUES,
        ROOT_MEDIA_DIR + ".thumbs",
        ROOT_MEDIA_DIR + ".editData"
    };

    for (const string &dir : DELETE_DIR_LIST) {
        if (!MediaFileUtils::DeleteDir(dir)) {
            MEDIA_ERR_LOG("Delete dir %{public}s failed", dir.c_str());
            continue;
        }
        if (!MediaFileUtils::CreateDirectory(dir)) {
            MEDIA_ERR_LOG("Create dir %{public}s failed", dir.c_str());
        };
    }

    string photoThumbsPath = ROOT_MEDIA_DIR + ".thumbs/Photo";
    if (!MediaFileUtils::CreateDirectory(photoThumbsPath)) {
        MEDIA_ERR_LOG("Create dir %{public}s failed", photoThumbsPath.c_str());
    };

    return E_OK;
}

static bool CheckOprnObject(OperationObject object)
{
    const set<OperationObject> validOprnObjectet = {
        OperationObject::FILESYSTEM_PHOTO,
        OperationObject::FILESYSTEM_AUDIO
    };
    if (validOprnObjectet.find(object) == validOprnObjectet.end()) {
        MEDIA_ERR_LOG("input OperationObject %{public}d error!", object);
        return false;
    }
    return true;
}

static OperationObject GetOprnObjectByMediaType(int32_t type)
{
    switch (type) {
        case MediaType::MEDIA_TYPE_IMAGE:
        case MediaType::MEDIA_TYPE_VIDEO: {
            return OperationObject::FILESYSTEM_PHOTO;
        }
        case MediaType::MEDIA_TYPE_AUDIO: {
            return OperationObject::FILESYSTEM_AUDIO;
        }
        case MediaType::MEDIA_TYPE_FILE: {
            return OperationObject::FILESYSTEM_ASSET;
        }
        default: {
            return OperationObject::UNKNOWN_OBJECT;
        }
    }
}

static shared_ptr<FileAsset> FetchFileAssetFromResultSet(
    const shared_ptr<NativeRdb::ResultSet> &resultSet, const vector<string> &columns)
{
    int32_t count = 0;
    int32_t currentRowIndex = 0;
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, nullptr, "resultSet is nullptr");
    CHECK_AND_RETURN_RET_LOG(
        resultSet->GetRowCount(count) == NativeRdb::E_OK, nullptr, "Cannot get row count of resultset");
    CHECK_AND_RETURN_RET_LOG(
        resultSet->GetRowIndex(currentRowIndex) == NativeRdb::E_OK, nullptr, "Cannot get row index of resultset");
    CHECK_AND_RETURN_RET_LOG(currentRowIndex >= 0 && currentRowIndex < count, nullptr, "Invalid row index");

    auto fileAsset = make_shared<FileAsset>();
    for (const auto &column : columns) {
        int32_t columnIndex = 0;
        CHECK_AND_RETURN_RET_LOG(resultSet->GetColumnIndex(column, columnIndex) == NativeRdb::E_OK,
            nullptr, "Can not get column %{private}s index", column.c_str());
        CHECK_AND_RETURN_RET_LOG(FILEASSET_MEMBER_MAP.find(column) != FILEASSET_MEMBER_MAP.end(), nullptr,
            "Can not find column %{private}s from member map", column.c_str());
        int32_t memberType = FILEASSET_MEMBER_MAP.at(column);
        switch (memberType) {
            case MEMBER_TYPE_INT32: {
                int32_t value = 0;
                CHECK_AND_RETURN_RET_LOG(resultSet->GetInt(columnIndex, value) == NativeRdb::E_OK, nullptr,
                    "Can not get int value from column %{private}s", column.c_str());
                auto &map = fileAsset->GetMemberMap();
                map[column] = value;
                break;
            }
            case MEMBER_TYPE_INT64: {
                int64_t value = 0;
                CHECK_AND_RETURN_RET_LOG(resultSet->GetLong(columnIndex, value) == NativeRdb::E_OK, nullptr,
                    "Can not get long value from column %{private}s", column.c_str());
                auto &map = fileAsset->GetMemberMap();
                map[column] = value;
                break;
            }
            case MEMBER_TYPE_STRING: {
                string value;
                CHECK_AND_RETURN_RET_LOG(resultSet->GetString(columnIndex, value) == NativeRdb::E_OK, nullptr,
                    "Can not get string value from column %{private}s", column.c_str());
                auto &map = fileAsset->GetMemberMap();
                map[column] = value;
                break;
            }
        }
    }
    return fileAsset;
}

shared_ptr<FileAsset> MediaLibraryAssetOperations::GetAssetFromResultSet(
    const shared_ptr<NativeRdb::ResultSet> &resultSet, const vector<string> &columns)
{
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, nullptr, "resultSet is nullptr");
    int32_t count = 0;
    CHECK_AND_RETURN_RET_LOG(resultSet->GetRowCount(count) == NativeRdb::E_OK, nullptr,
        "Cannot get row count of resultset");
    CHECK_AND_RETURN_RET_LOG(count == 1, nullptr, "ResultSet count is %{public}d, not 1", count);
    CHECK_AND_RETURN_RET_LOG(resultSet->GoToFirstRow() == NativeRdb::E_OK, nullptr, "Cannot go to first row");
    return FetchFileAssetFromResultSet(resultSet, columns);
}

static int32_t GetAssetVectorFromResultSet(const shared_ptr<NativeRdb::ResultSet> &resultSet,
    const vector<string> &columns, vector<shared_ptr<FileAsset>> &fileAssetVector)
{
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_HAS_DB_ERROR, "resultSet is nullptr");
    int32_t count = 0;
    CHECK_AND_RETURN_RET_LOG(resultSet->GetRowCount(count) == NativeRdb::E_OK, E_HAS_DB_ERROR,
        "Cannot get row count of resultset");
    CHECK_AND_RETURN_RET_LOG(count > 0, E_HAS_DB_ERROR, "ResultSet count is %{public}d", count);

    fileAssetVector.reserve(count);
    for (int32_t i = 0; i < count; i++) {
        CHECK_AND_RETURN_RET_LOG(
            resultSet->GoToNextRow() == NativeRdb::E_OK, E_HAS_DB_ERROR, "Failed to go to next row");
        auto fileAsset = FetchFileAssetFromResultSet(resultSet, columns);
        CHECK_AND_RETURN_RET_LOG(fileAsset != nullptr, E_HAS_DB_ERROR, "Failed to fetch fileAsset from resultSet");
        fileAssetVector.push_back(fileAsset);
    }
    return E_OK;
}

shared_ptr<FileAsset> MediaLibraryAssetOperations::GetFileAssetFromDb(const string &column,
    const string &value, OperationObject oprnObject, const vector<string> &columns, const string &networkId)
{
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryAssetOperations::GetFileAssetFromDb");
    if (!CheckOprnObject(oprnObject) || column.empty() || value.empty()) {
        return nullptr;
    }

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        return nullptr;
    }

    MediaLibraryCommand cmd(oprnObject, OperationType::QUERY, networkId);
    cmd.GetAbsRdbPredicates()->EqualTo(column, value);

    auto resultSet = rdbStore->Query(cmd, columns);
    if (resultSet == nullptr) {
        return nullptr;
    }
    return GetAssetFromResultSet(resultSet, columns);
}

static shared_ptr<NativeRdb::ResultSet> QueryByPredicates(AbsPredicates &predicates,
    OperationObject oprnObject, const vector<string> &columns, const string &networkId)
{
    if (!CheckOprnObject(oprnObject)) {
        return nullptr;
    }

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        return nullptr;
    }

    MediaLibraryCommand cmd(oprnObject, OperationType::QUERY, networkId);
    cmd.GetAbsRdbPredicates()->SetWhereClause(predicates.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(predicates.GetWhereArgs());
    cmd.GetAbsRdbPredicates()->SetOrder(predicates.GetOrder());
    return rdbStore->Query(cmd, columns);
}

shared_ptr<FileAsset> MediaLibraryAssetOperations::GetFileAssetFromDb(AbsPredicates &predicates,
    OperationObject oprnObject, const vector<string> &columns, const string &networkId)
{
    auto resultSet = QueryByPredicates(predicates, oprnObject, columns, networkId);
    if (resultSet == nullptr) {
        return nullptr;
    }
    return GetAssetFromResultSet(resultSet, columns);
}

int32_t MediaLibraryAssetOperations::GetFileAssetVectorFromDb(AbsPredicates &predicates, OperationObject oprnObject,
    vector<shared_ptr<FileAsset>> &fileAssetVector, const vector<string> &columns, const string &networkId)
{
    auto resultSet = QueryByPredicates(predicates, oprnObject, columns, networkId);
    if (resultSet == nullptr) {
        return E_HAS_DB_ERROR;
    }
    return GetAssetVectorFromResultSet(resultSet, columns, fileAssetVector);
}

shared_ptr<FileAsset> MediaLibraryAssetOperations::GetFileAssetByUri(const string &uri, bool isPhoto,
    const std::vector<std::string> &columns, const string &pendingStatus)
{
    if (uri.empty()) {
        MEDIA_ERR_LOG("fileUri is empty");
        return nullptr;
    }

    string id = MediaFileUtils::GetIdFromUri(uri);
    if (uri.empty() || (!MediaLibraryDataManagerUtils::IsNumber(id))) {
        return nullptr;
    }
    shared_ptr<FileAsset> fileAsset = make_shared<FileAsset>();
    MediaFileUri fileUri(uri);
    if (pendingStatus.empty() || !fileUri.IsApi10()) {
        if (isPhoto) {
            fileAsset = GetFileAssetFromDb(MediaColumn::MEDIA_ID, id, OperationObject::FILESYSTEM_PHOTO, columns);
        } else {
            fileAsset = GetFileAssetFromDb(MediaColumn::MEDIA_ID, id, OperationObject::FILESYSTEM_AUDIO, columns);
        }
    } else {
        string path = MediaFileUri::GetPathFromUri(uri, isPhoto);
        if (path.empty()) {
            if (isPhoto) {
                fileAsset = GetFileAssetFromDb(MediaColumn::MEDIA_ID, id, OperationObject::FILESYSTEM_PHOTO, columns);
            } else {
                fileAsset = GetFileAssetFromDb(MediaColumn::MEDIA_ID, id, OperationObject::FILESYSTEM_AUDIO, columns);
            }
        } else {
            fileAsset->SetPath(path);
            fileAsset->SetMediaType(MediaFileUtils::GetMediaType(path));
            int32_t timePending = stoi(pendingStatus);
            fileAsset->SetTimePending((timePending > 0) ? MediaFileUtils::UTCTimeSeconds() : timePending);
        }
    }

    if (fileAsset == nullptr) {
        return nullptr;
    }
    if (!isPhoto) {
        fileAsset->SetMediaType(MediaType::MEDIA_TYPE_AUDIO);
    }
    fileAsset->SetId(stoi(id));
    fileAsset->SetUri(uri);
    return fileAsset;
}

static inline string GetVirtualPath(const string &relativePath, const string &displayName)
{
    if (relativePath[relativePath.size() - 1] != SLASH_CHAR) {
        return relativePath + SLASH_CHAR + displayName;
    } else {
        return relativePath + displayName;
    }
}

static string GetAssetPackageName(const FileAsset &fileAsset, const string &bundleName)
{
    if (fileAsset.GetPhotoSubType() == static_cast<int32_t>(PhotoSubType::SCREENSHOT)) {
        if (fileAsset.GetMediaType() == static_cast<int32_t>(MediaType::MEDIA_TYPE_IMAGE) ||
            fileAsset.GetMediaType() == static_cast<int32_t>(MediaType::MEDIA_TYPE_PHOTO)) {
            return "截图";
        } else if (fileAsset.GetMediaType() == static_cast<int32_t>(MediaType::MEDIA_TYPE_VIDEO)) {
            return "屏幕录制";
        }
    }
    return PermissionUtils::GetPackageNameByBundleName(bundleName);
}

static void HandleDateAdded(const int64_t dateAdded, const MediaType type, ValuesBucket &outValues)
{
    outValues.PutLong(MediaColumn::MEDIA_DATE_ADDED, dateAdded);
    if (type != MEDIA_TYPE_PHOTO) {
        return;
    }
    outValues.PutString(PhotoColumn::PHOTO_DATE_YEAR,
        MediaFileUtils::StrCreateTimeByMilliseconds(PhotoColumn::PHOTO_DATE_YEAR_FORMAT, dateAdded));
    outValues.PutString(PhotoColumn::PHOTO_DATE_MONTH,
        MediaFileUtils::StrCreateTimeByMilliseconds(PhotoColumn::PHOTO_DATE_MONTH_FORMAT, dateAdded));
    outValues.PutString(PhotoColumn::PHOTO_DATE_DAY,
        MediaFileUtils::StrCreateTimeByMilliseconds(PhotoColumn::PHOTO_DATE_DAY_FORMAT, dateAdded));
    outValues.PutLong(MediaColumn::MEDIA_DATE_TAKEN, dateAdded);
}

static void HandleCallingPackage(MediaLibraryCommand &cmd, const FileAsset &fileAsset, ValuesBucket &outValues)
{
    if (!fileAsset.GetOwnerPackage().empty() && PermissionUtils::IsNativeSAApp()) {
        outValues.PutString(MediaColumn::MEDIA_OWNER_PACKAGE, fileAsset.GetOwnerPackage());

        int32_t callingUid = 0;
        ValueObject value;
        if (cmd.GetValueBucket().GetObject(MEDIA_DATA_CALLING_UID, value)) {
            value.GetInt(callingUid);
        }
        outValues.PutString(MediaColumn::MEDIA_OWNER_APPID,
            PermissionUtils::GetAppIdByBundleName(fileAsset.GetOwnerPackage(), callingUid));
        outValues.PutString(MediaColumn::MEDIA_PACKAGE_NAME, fileAsset.GetPackageName());
        return;
    }

    string bundleName;
    ValueObject valueBundleName;
    if (cmd.GetValueBucket().GetObject(MEDIA_DATA_DB_OWNER_PACKAGE, valueBundleName)) {
        valueBundleName.GetString(bundleName);
    }
    if (bundleName.empty()) {
        bundleName = cmd.GetBundleName();
    }
    outValues.PutString(MediaColumn::MEDIA_OWNER_PACKAGE, bundleName);

    string appId;
    ValueObject valueAppId;
    if (cmd.GetValueBucket().GetObject(MEDIA_DATA_DB_OWNER_APPID, valueAppId)) {
        valueAppId.GetString(appId);
    }
    if (appId.empty()) {
        appId = PermissionUtils::GetAppIdByBundleName(cmd.GetBundleName());
    }
    outValues.PutString(MediaColumn::MEDIA_OWNER_APPID, appId);
    string packageName;
    ValueObject valuePackageName;
    if (cmd.GetValueBucket().GetObject(MEDIA_DATA_DB_PACKAGE_NAME, valuePackageName)) {
        valuePackageName.GetString(packageName);
    }
    if (packageName.empty() && !cmd.GetBundleName().empty()) {
        packageName = GetAssetPackageName(fileAsset, cmd.GetBundleName());
    }
    if (!packageName.empty()) {
        outValues.PutString(MediaColumn::MEDIA_PACKAGE_NAME, packageName);
    }
}

static void HandleBurstPhoto(MediaLibraryCommand &cmd, ValuesBucket &outValues, const std::string displayName)
{
    if (!PermissionUtils::IsNativeSAApp()) {
        MEDIA_DEBUG_LOG("do not have permission to set burst_key or burst_cover_level");
        return;
    }

    string burstKey;
    ValueObject value;
    if (cmd.GetValueBucket().GetObject(PhotoColumn::PHOTO_BURST_KEY, value)) {
        value.GetString(burstKey);
    }
    if (!burstKey.empty()) {
        outValues.PutString(PhotoColumn::PHOTO_BURST_KEY, burstKey);
    }

    int32_t burstCoverLevel = 0;
    if (cmd.GetValueBucket().GetObject(PhotoColumn::PHOTO_BURST_COVER_LEVEL, value)) {
        value.GetInt(burstCoverLevel);
    }
    if (burstCoverLevel != 0) {
        outValues.PutInt(PhotoColumn::PHOTO_BURST_COVER_LEVEL, burstCoverLevel);
    }
    int32_t dirty = static_cast<int32_t>(DirtyTypes::TYPE_NEW);
    if (cmd.GetValueBucket().GetObject(PhotoColumn::PHOTO_DIRTY, value)) {
        value.GetInt(dirty);
    }
    if (dirty != static_cast<int32_t>(DirtyTypes::TYPE_NEW)) {
        outValues.PutInt(PhotoColumn::PHOTO_DIRTY, dirty);
    }
    stringstream result;
    for (int32_t i = 0; i < static_cast<int32_t>(displayName.length()); i++) {
        if (isdigit(displayName[i])) {
            result << displayName[i];
        }
    }
    outValues.Put(PhotoColumn::PHOTO_ID, result.str());
    outValues.PutInt(PhotoColumn::PHOTO_QUALITY, static_cast<int32_t>(MultiStagesPhotoQuality::FULL));
}

static void HandleIsTemp(MediaLibraryCommand &cmd, ValuesBucket &outValues)
{
    if (!PermissionUtils::IsNativeSAApp()) {
        MEDIA_DEBUG_LOG("do not have permission to set is_temp");
        return;
    }

    bool isTemp = 0;
    ValueObject value;
    if (cmd.GetValueBucket().GetObject(PhotoColumn::PHOTO_IS_TEMP, value)) {
        value.GetBool(isTemp);
    }
    outValues.PutBool(PhotoColumn::PHOTO_IS_TEMP, isTemp);
    return;
}

static void FillAssetInfo(MediaLibraryCommand &cmd, const FileAsset &fileAsset)
{
    // Fill basic file information into DB
    const string& displayName = fileAsset.GetDisplayName();
    int64_t nowTime = MediaFileUtils::UTCTimeMilliSeconds();
    ValuesBucket assetInfo;
    assetInfo.PutInt(MediaColumn::MEDIA_TYPE, fileAsset.GetMediaType());
    string extension = ScannerUtils::GetFileExtension(displayName);
    assetInfo.PutString(MediaColumn::MEDIA_MIME_TYPE,
        MimeTypeUtils::GetMimeTypeFromExtension(extension));
    assetInfo.PutString(MediaColumn::MEDIA_FILE_PATH, fileAsset.GetPath());
    if (cmd.GetApi() == MediaLibraryApi::API_OLD) {
        assetInfo.PutString(MediaColumn::MEDIA_RELATIVE_PATH,
            fileAsset.GetRelativePath());
        assetInfo.PutString(MediaColumn::MEDIA_VIRTURL_PATH,
            GetVirtualPath(fileAsset.GetRelativePath(), fileAsset.GetDisplayName()));
    } else {
        assetInfo.PutLong(MediaColumn::MEDIA_TIME_PENDING, fileAsset.GetTimePending());
    }
    assetInfo.PutString(MediaColumn::MEDIA_NAME, displayName);
    assetInfo.PutString(MediaColumn::MEDIA_TITLE,
        MediaFileUtils::GetTitleFromDisplayName(displayName));
    if (cmd.GetOprnObject() == OperationObject::FILESYSTEM_PHOTO) {
        assetInfo.PutInt(PhotoColumn::PHOTO_SUBTYPE, fileAsset.GetPhotoSubType());
        assetInfo.PutString(PhotoColumn::CAMERA_SHOT_KEY, fileAsset.GetCameraShotKey());
        HandleIsTemp(cmd, assetInfo);
        if (fileAsset.GetPhotoSubType() == static_cast<int32_t>(PhotoSubType::BURST)) {
            HandleBurstPhoto(cmd, assetInfo, displayName);
        }
    }

    HandleCallingPackage(cmd, fileAsset, assetInfo);

    assetInfo.PutString(MediaColumn::MEDIA_DEVICE_NAME, cmd.GetDeviceName());
    HandleDateAdded(nowTime,
        cmd.GetOprnObject() == OperationObject::FILESYSTEM_PHOTO ? MEDIA_TYPE_PHOTO : MEDIA_TYPE_DEFAULT,
        assetInfo);
    cmd.SetValueBucket(assetInfo);
}

static void GetUriPermissionValuesBucket(string &tableName, ValuesBucket &valuesBucket,
    string appId, int64_t fileId)
{
    TableType mediaType;
    if (tableName == PhotoColumn::PHOTOS_TABLE) {
        mediaType = TableType::TYPE_PHOTOS;
    } else {
        mediaType = TableType::TYPE_AUDIOS;
    }
    valuesBucket.Put(AppUriPermissionColumn::FILE_ID, static_cast<int32_t>(fileId));
    valuesBucket.Put(AppUriPermissionColumn::URI_TYPE, static_cast<int32_t>(mediaType));
    valuesBucket.Put(AppUriPermissionColumn::PERMISSION_TYPE,
        AppUriPermissionColumn::PERMISSION_PERSIST_READ_WRITE);
    valuesBucket.Put(AppUriPermissionColumn::APP_ID, appId);
    valuesBucket.Put(AppUriPermissionColumn::DATE_MODIFIED, MediaFileUtils::UTCTimeMilliSeconds());
}

int32_t MediaLibraryAssetOperations::InsertAssetInDb(std::shared_ptr<TransactionOperations> trans,
    MediaLibraryCommand &cmd, const FileAsset &fileAsset)
{
    // All values inserted in this function are the base property for files
    if (trans == nullptr) {
        return E_HAS_DB_ERROR;
    }

    if (!fileAsset.GetPath().empty() && MediaFileUtils::IsFileExists(fileAsset.GetPath())) {
        MEDIA_ERR_LOG("file %{private}s exists now", fileAsset.GetPath().c_str());
        return E_FILE_EXIST;
    }
    int32_t callingUid = 0;
    ValueObject value;
    if (cmd.GetValueBucket().GetObject(MEDIA_DATA_CALLING_UID, value)) {
        value.GetInt(callingUid);
    }
    FillAssetInfo(cmd, fileAsset);

    int64_t outRowId = -1;
    int32_t errCode = trans->Insert(cmd, outRowId);
    if (errCode != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Insert into db failed, errCode = %{public}d", errCode);
        return E_HAS_DB_ERROR;
    }
    string appId;
    if (PermissionUtils::IsNativeSAApp()) {
        appId = PermissionUtils::GetAppIdByBundleName(fileAsset.GetOwnerPackage(), callingUid);
    } else {
        appId = PermissionUtils::GetAppIdByBundleName(cmd.GetBundleName());
    }
    auto fileId = outRowId;
    string tableName = cmd.GetTableName();
    ValuesBucket valuesBucket;
    if (!appId.empty()) {
        int64_t tmpOutRowId = -1;
        GetUriPermissionValuesBucket(tableName, valuesBucket, appId, fileId);
        MediaLibraryCommand cmd(Uri(MEDIALIBRARY_GRANT_URIPERM_URI), valuesBucket);
        errCode = trans->Insert(cmd, tmpOutRowId);
        if (errCode != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Insert into db failed, errCode = %{public}d", errCode);
            return E_HAS_DB_ERROR;
        }
        MEDIA_INFO_LOG("insert uripermission success, rowId = %{public}d", (int)outRowId);
    }
    MEDIA_INFO_LOG("insert success, rowId = %{public}d", (int)outRowId);
    return static_cast<int32_t>(outRowId);
}

static bool CheckTypeFromRootDir(const std::string &rootDirName, int32_t type)
{
    // "Camera/"
    if (!strcmp(rootDirName.c_str(), CAMERA_DIR_VALUES.c_str())) {
        if (type == MEDIA_TYPE_IMAGE || type == MEDIA_TYPE_VIDEO) {
            return true;
        }
    }
    // "Videos/"
    if (!strcmp(rootDirName.c_str(), VIDEO_DIR_VALUES.c_str())) {
        if (type == MEDIA_TYPE_VIDEO) {
            return true;
        }
    }
    // "Pictures/"
    if (!strcmp(rootDirName.c_str(), PIC_DIR_VALUES.c_str())) {
        if (type == MEDIA_TYPE_IMAGE) {
            return true;
        }
    }
    // "Audios/"
    if (!strcmp(rootDirName.c_str(), AUDIO_DIR_VALUES.c_str())) {
        if (type == MEDIA_TYPE_AUDIO) {
            return true;
        }
    }
    // "Docs/Documents/" and "Docs/Download"
    if (!strcmp(rootDirName.c_str(), DOCS_PATH.c_str())) {
        return true;
    }
    MEDIA_ERR_LOG("Cannot match rootDir %{private}s and mediaType %{public}d",
        rootDirName.c_str(), type);
    return false;
}

int32_t MediaLibraryAssetOperations::CheckWithType(bool isContains, const string &displayName,
    const string &extention, int32_t mediaType)
{
    string name = isContains ? displayName : extention;
    int32_t errCode =  isContains ? CheckDisplayNameWithType(name, mediaType) : CheckExtWithType(name, mediaType);
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode,
        "Failed to Check Dir and extention, (displayName or extention)=%{private}s, mediaType=%{public}d",
        name.c_str(), mediaType);
    return errCode;
}

int32_t MediaLibraryAssetOperations::CheckDisplayNameWithType(const string &displayName, int32_t mediaType)
{
    int32_t ret = MediaFileUtils::CheckDisplayName(displayName);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, E_INVALID_DISPLAY_NAME, "Check DisplayName failed, "
        "displayName=%{private}s", displayName.c_str());

    string ext = MediaFileUtils::GetExtensionFromPath(displayName);
    CHECK_AND_RETURN_RET_LOG(!ext.empty(), E_INVALID_DISPLAY_NAME, "invalid extension, displayName=%{private}s",
        displayName.c_str());

    auto typeFromExt = MediaFileUtils::GetMediaType(displayName);
    CHECK_AND_RETURN_RET_LOG(typeFromExt == mediaType, E_CHECK_MEDIATYPE_MATCH_EXTENSION_FAIL,
        "cannot match, mediaType=%{public}d, ext=%{private}s, type from ext=%{public}d",
        mediaType, ext.c_str(), typeFromExt);
    return E_OK;
}

int32_t MediaLibraryAssetOperations::CheckExtWithType(const string &extention, int32_t mediaType)
{
    string mimeType = MimeTypeUtils::GetMimeTypeFromExtension(extention);
    auto typeFromExt = MimeTypeUtils::GetMediaTypeFromMimeType(mimeType);
    CHECK_AND_RETURN_RET_LOG(typeFromExt == mediaType, E_CHECK_MEDIATYPE_MATCH_EXTENSION_FAIL,
        "cannot match, mediaType=%{public}d, ext=%{public}s, type from ext=%{public}d",
        mediaType, extention.c_str(), typeFromExt);
    return E_OK;
}

int32_t MediaLibraryAssetOperations::CheckRelativePathWithType(const string &relativePath, int32_t mediaType)
{
    int32_t ret = MediaFileUtils::CheckRelativePath(relativePath);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, E_INVALID_PATH, "Check relativePath failed, "
        "relativePath=%{private}s", relativePath.c_str());

    // get rootdir and check if it match mediatype
    string rootDirName;
    MediaFileUtils::GetRootDirFromRelativePath(relativePath, rootDirName);
    CHECK_AND_RETURN_RET_LOG(!rootDirName.empty(), E_INVALID_PATH, "Cannot get rootdirName");

    bool isValid = CheckTypeFromRootDir(rootDirName, mediaType);
    CHECK_AND_RETURN_RET(isValid, E_CHECK_MEDIATYPE_FAIL);
    return E_OK;
}

void MediaLibraryAssetOperations::GetAssetRootDir(int32_t mediaType, string &rootDirPath)
{
    map<int, string> rootDir = {
        { MEDIA_TYPE_FILE, DOCUMENT_BUCKET + SLASH_CHAR },
        { MEDIA_TYPE_VIDEO, PHOTO_BUCKET + SLASH_CHAR },
        { MEDIA_TYPE_IMAGE, PHOTO_BUCKET + SLASH_CHAR },
        { MEDIA_TYPE_AUDIO, AUDIO_BUCKET + SLASH_CHAR },
    };
    if (rootDir.count(mediaType) == 0) {
        rootDirPath = rootDir[MEDIA_TYPE_FILE];
    } else {
        rootDirPath = rootDir[mediaType];
    }
}

int32_t MediaLibraryAssetOperations::SetAssetPathInCreate(FileAsset &fileAsset,
    std::shared_ptr<TransactionOperations> trans)
{
    if (!fileAsset.GetPath().empty()) {
        return E_OK;
    }
    string extension = MediaFileUtils::GetExtensionFromPath(fileAsset.GetDisplayName());
    string filePath;
    int32_t uniqueId = CreateAssetUniqueId(fileAsset.GetMediaType(), trans);
    int32_t errCode = CreateAssetPathById(uniqueId, fileAsset.GetMediaType(), extension, filePath);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("Create Asset Path failed, errCode=%{public}d", errCode);
        return errCode;
    }

    // filePath can not be empty
    fileAsset.SetPath(filePath);
    return E_OK;
}

int32_t MediaLibraryAssetOperations::SetAssetPath(FileAsset &fileAsset, const string &extension,
    std::shared_ptr<TransactionOperations> trans)
{
    string filePath;
    int32_t uniqueId = CreateAssetUniqueId(fileAsset.GetMediaType(), trans);
    int32_t errCode = CreateAssetPathById(uniqueId, fileAsset.GetMediaType(), extension, filePath);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("Create Asset Path failed, errCode=%{public}d", errCode);
        return errCode;
    }

    // filePath can not be empty
    fileAsset.SetPath(filePath);
    string fileName = MediaFileUtils::GetFileName(filePath);
    string displayName = fileName.substr(0, fileName.find('_')) + '_' + fileName.substr(fileName.rfind('_') + 1);
    fileAsset.SetDisplayName(displayName);
    return E_OK;
}

int32_t MediaLibraryAssetOperations::DeleteAssetInDb(MediaLibraryCommand &cmd)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        return E_HAS_DB_ERROR;
    }

    string strDeleteCondition = cmd.GetAbsRdbPredicates()->GetWhereClause();
    if (strDeleteCondition.empty()) {
        string strRow = cmd.GetOprnFileId();
        if (strRow.empty() || !MediaLibraryDataManagerUtils::IsNumber(strRow)) {
            MEDIA_ERR_LOG("MediaLibraryAssetOperations DeleteFile: Index not digit, fileIdStr=%{private}s",
                strRow.c_str());
            return E_INVALID_FILEID;
        }
        cmd.GetAbsRdbPredicates()->EqualTo(MediaColumn::MEDIA_ID, strRow);
    }

    int32_t deletedRows = E_HAS_DB_ERROR;
    int32_t result = rdbStore->Delete(cmd, deletedRows);
    if (result != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Delete operation failed. Result %{public}d.", result);
    }

    return deletedRows;
}


int32_t MediaLibraryAssetOperations::UpdateFileName(MediaLibraryCommand &cmd,
    const shared_ptr<FileAsset> &fileAsset, bool &isNameChanged)
{
    ValuesBucket &values = cmd.GetValueBucket();
    ValueObject valueObject;
    string newTitle;
    string newDisplayName;
    bool containsTitle = false;
    bool containsDisplayName = false;

    if (values.GetObject(MediaColumn::MEDIA_TITLE, valueObject)) {
        valueObject.GetString(newTitle);
        containsTitle = true;
    }
    if (values.GetObject(MediaColumn::MEDIA_NAME, valueObject)) {
        valueObject.GetString(newDisplayName);
        containsDisplayName = true;
    }
    if ((!containsTitle) && (!containsDisplayName)) {
        // do not need to update
        return E_OK;
    }
    if (containsTitle && containsDisplayName &&
        (MediaFileUtils::GetTitleFromDisplayName(newDisplayName) != newTitle)) {
        MEDIA_ERR_LOG("new displayName [%{private}s] and new title [%{private}s] is not same",
            newDisplayName.c_str(), newTitle.c_str());
        return E_INVALID_DISPLAY_NAME;
    }
    if (!containsTitle) {
        newTitle = MediaFileUtils::GetTitleFromDisplayName(newDisplayName);
    }
    if (!containsDisplayName) {
        newDisplayName = newTitle + "." + MediaFileUtils::SplitByChar(fileAsset->GetDisplayName(), '.');
    }

    int32_t ret = CheckDisplayNameWithType(newDisplayName, fileAsset->GetMediaType());
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "Input displayName invalid %{private}s", newDisplayName.c_str());
    values.PutString(MediaColumn::MEDIA_TITLE, newTitle);
    values.PutString(MediaColumn::MEDIA_NAME, newDisplayName);
    isNameChanged = true;
    return E_OK;
}

int32_t MediaLibraryAssetOperations::SetUserComment(MediaLibraryCommand &cmd,
    const shared_ptr<FileAsset> &fileAsset)
{
    ValuesBucket &values = cmd.GetValueBucket();
    ValueObject valueObject;
    string newUserComment;

    if (values.GetObject(PhotoColumn::PHOTO_USER_COMMENT, valueObject)) {
        valueObject.GetString(newUserComment);
    } else {
        return E_OK;
    }

    uint32_t err = 0;
    SourceOptions opts;
    string filePath = fileAsset->GetFilePath();
    string extension = MediaFileUtils::GetExtensionFromPath(filePath);
    opts.formatHint = "image/" + extension;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(filePath, opts, err);
    if (err != 0 || imageSource == nullptr) {
        MEDIA_ERR_LOG("Failed to obtain image source, err = %{public}d", err);
        return E_OK;
    }

    string userComment;
    err = imageSource->GetImagePropertyString(0, PHOTO_DATA_IMAGE_USER_COMMENT, userComment);
    if (err != 0) {
        MEDIA_ERR_LOG("Image does not exist user comment in exif, no need to modify");
        return E_OK;
    }
    err = imageSource->ModifyImageProperty(0, PHOTO_DATA_IMAGE_USER_COMMENT, newUserComment, filePath);
    if (err != 0) {
        MEDIA_ERR_LOG("Modify image property user comment failed");
    }

    return E_OK;
}

int32_t MediaLibraryAssetOperations::UpdateRelativePath(MediaLibraryCommand &cmd,
    const shared_ptr<FileAsset> &fileAsset, bool &isNameChanged)
{
    string newRelativePath;
    ValuesBucket &values = cmd.GetValueBucket();
    ValueObject valueObject;
    if (values.GetObject(MediaColumn::MEDIA_RELATIVE_PATH, valueObject)) {
        valueObject.GetString(newRelativePath);
    } else {
        // relativePath is not modified
        return E_OK;
    }
    MediaFileUtils::FormatRelativePath(newRelativePath);

    if (newRelativePath == fileAsset->GetRelativePath()) {
        // relativepath has not been modified
        return E_OK;
    }

    int32_t errCode = CheckRelativePathWithType(newRelativePath, fileAsset->GetMediaType());
    if (errCode != E_SUCCESS) {
        MEDIA_ERR_LOG("Check RelativePath failed");
        return errCode;
    }
    values.Delete(MediaColumn::MEDIA_RELATIVE_PATH);
    values.PutString(MediaColumn::MEDIA_RELATIVE_PATH, newRelativePath);

    isNameChanged = true;
    return E_OK;
}

void MediaLibraryAssetOperations::UpdateVirtualPath(MediaLibraryCommand &cmd,
    const shared_ptr<FileAsset> &fileAsset)
{
    string relativePath;
    string displayName;
    ValuesBucket &values = cmd.GetValueBucket();
    ValueObject valueObject;

    if (values.GetObject(MediaColumn::MEDIA_NAME, valueObject)) {
        valueObject.GetString(displayName);
    } else {
        displayName = fileAsset->GetDisplayName();
    }

    if (values.GetObject(MediaColumn::MEDIA_RELATIVE_PATH, valueObject)) {
        valueObject.GetString(relativePath);
    } else {
        relativePath = fileAsset->GetRelativePath();
    }

    if (relativePath.back() != '/') {
        relativePath += '/';
    }
    string virtualPath = relativePath + displayName;
    values.PutString(MediaColumn::MEDIA_VIRTURL_PATH, virtualPath);
}

int32_t MediaLibraryAssetOperations::UpdateFileInDb(MediaLibraryCommand &cmd)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        return E_HAS_DB_ERROR;
    }

    int32_t updateRows = 0;
    int32_t result = rdbStore->Update(cmd, updateRows);
    if (result != NativeRdb::E_OK || updateRows <= 0) {
        MEDIA_ERR_LOG("Update File failed. Result %{public}d.", result);
        return E_HAS_DB_ERROR;
    }

    return updateRows;
}

int32_t MediaLibraryAssetOperations::OpenFileWithPrivacy(const string &filePath, const string &mode,
    const string &fileId)
{
    std::string absFilePath;
    if (!PathToRealPath(filePath, absFilePath)) {
        MEDIA_ERR_LOG("Failed to get real path: %{private}s", filePath.c_str());
        return E_ERR;
    }

    return MediaPrivacyManager(absFilePath, mode, fileId).Open();
}

static int32_t SetPendingTime(const shared_ptr<FileAsset> &fileAsset, int64_t pendingTime)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        return E_HAS_DB_ERROR;
    }

    MediaLibraryCommand updatePendingCmd(GetOprnObjectByMediaType(fileAsset->GetMediaType()),
        OperationType::UPDATE);
    updatePendingCmd.GetAbsRdbPredicates()->EqualTo(MediaColumn::MEDIA_ID,
        to_string(fileAsset->GetId()));
    ValuesBucket values;
    values.PutLong(MediaColumn::MEDIA_TIME_PENDING, pendingTime);
    updatePendingCmd.SetValueBucket(values);
    int32_t rowId = 0;
    int32_t result = rdbStore->Update(updatePendingCmd, rowId);
    if (result != NativeRdb::E_OK || rowId <= 0) {
        MEDIA_ERR_LOG("Update File pending failed. Result %{public}d.", result);
        return E_HAS_DB_ERROR;
    }
    return E_OK;
}

static int32_t CreateFileAndSetPending(const shared_ptr<FileAsset> &fileAsset, int64_t pendingTime)
{
    int32_t errCode = MediaFileUtils::CreateAsset(fileAsset->GetPath());
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("Create asset failed, path=%{private}s", fileAsset->GetPath().c_str());
        return errCode;
    }

    return SetPendingTime(fileAsset, pendingTime);
}

static int32_t SolvePendingStatus(const shared_ptr<FileAsset> &fileAsset, const string &mode)
{
    int64_t pendingTime = fileAsset->GetTimePending();
    if (pendingTime != 0) {
        if (mode == MEDIA_FILEMODE_READONLY) {
            MEDIA_ERR_LOG("FileAsset [%{private}s] pending status is %{public}ld and open mode is READ_ONLY",
                fileAsset->GetUri().c_str(), (long) pendingTime);
            return E_IS_PENDING_ERROR;
        }
        string networkId = MediaFileUtils::GetNetworkIdFromUri(fileAsset->GetUri());
        if (!networkId.empty()) {
            MEDIA_ERR_LOG("Can not open remote [%{private}s] pending file", networkId.c_str());
            return E_IS_PENDING_ERROR;
        }
        if (pendingTime == UNCREATE_FILE_TIMEPENDING) {
            int32_t errCode = CreateFileAndSetPending(fileAsset, UNCLOSE_FILE_TIMEPENDING);
            return errCode;
        }
        if (pendingTime == UNOPEN_FILE_COMPONENT_TIMEPENDING) {
            int32_t errCode = SetPendingTime(fileAsset, UNCLOSE_FILE_TIMEPENDING);
            return errCode;
        }
    }
    return E_OK;
}

static int32_t CreateDirectoryAndAsset(const string path)
{
    string dir = MediaFileUtils::GetParentPath(path);
    if (!MediaFileUtils::CreateDirectory(dir)) {
        MEDIA_ERR_LOG("Create dir failed, dir=%{private}s", dir.c_str());
        return E_INVALID_VALUES;
    }
    int32_t errCode = MediaFileUtils::CreateAsset(path);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("Create asset failed, path=%{private}s", path.c_str());
        return errCode;
    }
    return E_OK;
}

static int32_t SolveMovingPhotoVideoCreation(const string &imagePath, const string &mode, bool isMovingPhotoVideo)
{
    if (mode == MEDIA_FILEMODE_READONLY || !isMovingPhotoVideo) {
        return E_OK;
    }
    string videoPath = MediaFileUtils::GetMovingPhotoVideoPath(imagePath);
    if (MediaFileUtils::IsFileExists(videoPath)) {
        return E_OK;
    }
    int32_t errCode = MediaFileUtils::CreateAsset(videoPath);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("Create moving photo asset failed, path=%{private}s", videoPath.c_str());
        return errCode;
    }
    return E_OK;
}

int32_t MediaLibraryAssetOperations::OpenAsset(const shared_ptr<FileAsset> &fileAsset, const string &mode,
    MediaLibraryApi api, bool isMovingPhotoVideo)
{
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryAssetOperations::OpenAsset");

    if (fileAsset == nullptr) {
        return E_INVALID_VALUES;
    }

    string lowerMode = mode;
    transform(lowerMode.begin(), lowerMode.end(), lowerMode.begin(), ::tolower);
    if (!MediaFileUtils::CheckMode(lowerMode)) {
        return E_INVALID_MODE;
    }

    string path;
    if (api == MediaLibraryApi::API_10) {
        int32_t errCode = SolvePendingStatus(fileAsset, mode);
        if (errCode != E_OK) {
            MEDIA_ERR_LOG("Solve pending status failed, errCode=%{public}d", errCode);
            return errCode;
        }
        path = fileAsset->GetPath();
        SolveMovingPhotoVideoCreation(path, mode, isMovingPhotoVideo);
    } else {
        // If below API10, TIME_PENDING is 0 after asset created, so if file is not exist, create an empty one
        if (!MediaFileUtils::IsFileExists(fileAsset->GetPath())) {
            MEDIA_INFO_LOG("create empty file for %{public}s, path: %{private}s", fileAsset->GetUri().c_str(),
                fileAsset->GetPath().c_str());
            int32_t errCode = CreateDirectoryAndAsset(fileAsset->GetPath());
            CHECK_AND_RETURN_RET(errCode == E_OK, errCode);
        }
        path = MediaFileUtils::UpdatePath(fileAsset->GetPath(), fileAsset->GetUri());
    }

    string fileId = MediaFileUtils::GetIdFromUri(fileAsset->GetUri());
    int32_t fd = OpenFileWithPrivacy(path, lowerMode, fileId);
    if (fd < 0) {
        MEDIA_ERR_LOG("open file fd %{public}d, errno %{public}d", fd, errno);
        return E_HAS_FS_ERROR;
    }
    tracer.Start("AddWatchList");
    if (mode.find(MEDIA_FILEMODE_WRITEONLY) != string::npos && !isMovingPhotoVideo) {
        auto watch = MediaLibraryInotify::GetInstance();
        if (watch != nullptr) {
            MEDIA_INFO_LOG("enter inotify, path = %{public}s, fileId = %{public}d",
                DfxUtils::GetSafePath(path).c_str(), fileAsset->GetId());
            watch->AddWatchList(path, fileAsset->GetUri(), MediaLibraryApi::API_10);
        }
    }
    tracer.Finish();
    return fd;
}

int32_t MediaLibraryAssetOperations::CloseAsset(const shared_ptr<FileAsset> &fileAsset, bool isCreateThumbSync)
{
    if (fileAsset == nullptr) {
        return E_INVALID_VALUES;
    }

    // remove inotify event since there is close cmd
    auto watch = MediaLibraryInotify::GetInstance();
    if (watch != nullptr) {
        string uri = fileAsset->GetUri();
        watch->RemoveByFileUri(uri, MediaLibraryApi::API_10);
        MEDIA_DEBUG_LOG("watch RemoveByFileUri, uri:%{private}s", uri.c_str());
    }

    string path = fileAsset->GetPath();
    // if pending == 0, scan
    // if pending == UNCREATE_FILE_TIMEPENDING, not occur under normal conditions
    // if pending == UNCLOSE_FILE_TIMEPENDING, set pending = 0 and scan
    // if pending == UNOPEN_FILE_COMPONENT_TIMEPENDING, not allowed to close
    // if pending is timestamp, do nothing
    if (fileAsset->GetTimePending() == 0 || fileAsset->GetTimePending() == UNCLOSE_FILE_TIMEPENDING) {
        if (fileAsset->GetTimePending() == UNCLOSE_FILE_TIMEPENDING) {
            ScanFile(path, isCreateThumbSync, false);
        } else {
            ScanFile(path, isCreateThumbSync, true);
        }
        return E_OK;
    } else if (fileAsset->GetTimePending() == UNCREATE_FILE_TIMEPENDING ||
        fileAsset->GetTimePending() == UNOPEN_FILE_COMPONENT_TIMEPENDING) {
        MEDIA_ERR_LOG("This asset [%{public}d] pending status cannot close", fileAsset->GetId());
        return E_IS_PENDING_ERROR;
    } else if (fileAsset->GetTimePending() > 0) {
        MEDIA_WARN_LOG("This asset [%{public}d] is in pending", fileAsset->GetId());
        return E_OK;
    } else {
        MEDIA_ERR_LOG("This asset [%{public}d] pending status is invalid", fileAsset->GetId());
        return E_INVALID_VALUES;
    }
}

int32_t MediaLibraryAssetOperations::OpenHighlightCover(MediaLibraryCommand &cmd, const string &mode)
{
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryAssetOperations::OpenHighlightCover");
    string uriStr = cmd.GetUriStringWithoutSegment();
    string path = MediaFileUtils::GetHighlightPath(uriStr);
    if (path.length() == 0) {
        MEDIA_ERR_LOG("Open highlight cover invalid uri : %{public}s", uriStr.c_str());
        return E_INVALID_URI;
    }
    
    shared_ptr<FileAsset> fileAsset = make_shared<FileAsset>();
    
    fileAsset->SetPath(path);
    fileAsset->SetUri(uriStr);
    
    return OpenAsset(fileAsset, mode, cmd.GetApi(), false);
}

int32_t MediaLibraryAssetOperations::OpenHighlightVideo(MediaLibraryCommand &cmd, const string &mode)
{
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryAssetOperations::OpenHighlightVideo");
    string uriStr = cmd.GetUriStringWithoutSegment();
    string path = MediaFileUtils::GetHighlightVideoPath(uriStr);
    if (path.length() == 0) {
        MEDIA_ERR_LOG("Open highlight video invalid uri : %{public}s", uriStr.c_str());
        return E_INVALID_URI;
    }
    shared_ptr<FileAsset> fileAsset = make_shared<FileAsset>();
    fileAsset->SetPath(path);
    fileAsset->SetUri(uriStr);
    
    return OpenAsset(fileAsset, mode, cmd.GetApi(), false);
}

void MediaLibraryAssetOperations::InvalidateThumbnail(const string &fileId, int32_t type)
{
    string tableName;
    switch (type) {
        case MediaType::MEDIA_TYPE_IMAGE:
        case MediaType::MEDIA_TYPE_VIDEO: {
            tableName = PhotoColumn::PHOTOS_TABLE;
            break;
        }
        case MediaType::MEDIA_TYPE_AUDIO: {
            tableName = AudioColumn::AUDIOS_TABLE;
            break;
        }
        default: {
            MEDIA_ERR_LOG("Can not match this type %{public}d", type);
            return;
        }
    }
    ThumbnailService::GetInstance()->HasInvalidateThumbnail(fileId, tableName);
}

void MediaLibraryAssetOperations::ScanFile(const string &path, bool isCreateThumbSync, bool isInvalidateThumb,
    bool isForceScan, int32_t fileId)
{
    // Force Scan means medialibrary will scan file without checking E_SCANNED
    shared_ptr<ScanAssetCallback> scanAssetCallback = make_shared<ScanAssetCallback>();
    if (scanAssetCallback == nullptr) {
        MEDIA_ERR_LOG("Failed to create scan file callback object");
        return;
    }
    if (isCreateThumbSync) {
        scanAssetCallback->SetSync(true);
    }
    if (!isInvalidateThumb) {
        scanAssetCallback->SetIsInvalidateThumb(false);
    }

    int ret = MediaScannerManager::GetInstance()->ScanFileSync(path, scanAssetCallback, MediaLibraryApi::API_10,
        isForceScan, fileId);
    if (ret != 0) {
        MEDIA_ERR_LOG("Scan file failed with error: %{public}d", ret);
    }
}

void MediaLibraryAssetOperations::ScanFileWithoutAlbumUpdate(const string &path, bool isCreateThumbSync,
    bool isInvalidateThumb, bool isForceScan, int32_t fileId)
{
    // Force Scan means medialibrary will scan file without checking E_SCANNED
    shared_ptr<ScanAssetCallback> scanAssetCallback = make_shared<ScanAssetCallback>();
    if (scanAssetCallback == nullptr) {
        MEDIA_ERR_LOG("Failed to create scan file callback object");
        return;
    }
    if (isCreateThumbSync) {
        scanAssetCallback->SetSync(true);
    }
    if (!isInvalidateThumb) {
        scanAssetCallback->SetIsInvalidateThumb(false);
    }

    int ret = MediaScannerManager::GetInstance()->ScanFileSyncWithoutAlbumUpdate(path, scanAssetCallback,
        MediaLibraryApi::API_10, isForceScan, fileId);
    if (ret != 0) {
        MEDIA_ERR_LOG("Scan file failed with error: %{public}d", ret);
    }
}

string MediaLibraryAssetOperations::GetEditDataDirPath(const string &path)
{
    if (path.length() < ROOT_MEDIA_DIR.length()) {
        return "";
    }
    return MEDIA_EDIT_DATA_DIR + path.substr(ROOT_MEDIA_DIR.length());
}

string MediaLibraryAssetOperations::GetEditDataSourcePath(const string &path)
{
    string parentPath = GetEditDataDirPath(path);
    if (parentPath.empty()) {
        return "";
    }
    return parentPath + "/source." + MediaFileUtils::GetExtensionFromPath(path);
}

string MediaLibraryAssetOperations::GetEditDataPath(const string &path)
{
    string parentPath = GetEditDataDirPath(path);
    if (parentPath.empty()) {
        return "";
    }
    return parentPath + "/editdata";
}

string MediaLibraryAssetOperations::GetEditDataCameraPath(const string &path)
{
    string parentPath = GetEditDataDirPath(path);
    if (parentPath.empty()) {
        return "";
    }
    return parentPath + "/editdata_camera";
}

string MediaLibraryAssetOperations::GetAssetCacheDir()
{
    string cacheOwner = MediaLibraryBundleManager::GetInstance()->GetClientBundleName();
    if (cacheOwner.empty()) {
        cacheOwner = "common"; // Create cache file in common dir if there is no bundleName.
    }
    return MEDIA_CACHE_DIR + cacheOwner;
}

static void UpdateAlbumsAndSendNotifyInTrash(AsyncTaskData *data)
{
    if (data == nullptr) {
        return;
    }
    DeleteNotifyAsyncTaskData* notifyData = static_cast<DeleteNotifyAsyncTaskData*>(data);

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("Can not get rdbstore");
        return;
    }
    MediaLibraryRdbUtils::UpdateSystemAlbumInternal(rdbStore);
    MediaLibraryRdbUtils::UpdateUserAlbumByUri(rdbStore, {notifyData->notifyUri});
    MediaLibraryRdbUtils::UpdateSourceAlbumByUri(rdbStore, {notifyData->notifyUri});
    MediaLibraryRdbUtils::UpdateAnalysisAlbumByUri(rdbStore, {notifyData->notifyUri});

    auto watch = MediaLibraryNotify::GetInstance();
    if (watch == nullptr) {
        MEDIA_ERR_LOG("Can not get MediaLibraryNotify");
        return;
    }
    if (notifyData->trashDate > 0) {
        watch->Notify(notifyData->notifyUri, NotifyType::NOTIFY_REMOVE);
        watch->Notify(notifyData->notifyUri, NotifyType::NOTIFY_ALBUM_REMOVE_ASSET);
    } else {
        watch->Notify(notifyData->notifyUri, NotifyType::NOTIFY_ADD);
        watch->Notify(notifyData->notifyUri, NotifyType::NOTIFY_ALBUM_ADD_ASSET);
    }

    int trashAlbumId = watch->GetAlbumIdBySubType(PhotoAlbumSubType::TRASH);
    if (trashAlbumId <= 0) {
        return;
    }
    NotifyType type = (notifyData->trashDate > 0) ? NotifyType::NOTIFY_ALBUM_ADD_ASSET :
        NotifyType::NOTIFY_ALBUM_REMOVE_ASSET;
    watch->Notify(notifyData->notifyUri, type, trashAlbumId);
    vector<int64_t> formIds;
    MediaLibraryFormMapOperations::GetFormMapFormId(notifyData->notifyUri, formIds);
    if (!formIds.empty()) {
        MediaLibraryFormMapOperations::PublishedChange("", formIds, false);
    }
}

int32_t MediaLibraryAssetOperations::SendTrashNotify(MediaLibraryCommand &cmd, int32_t rowId, const string &extraUri)
{
    ValueObject value;
    int64_t trashDate = 0;
    if (!cmd.GetValueBucket().GetObject(PhotoColumn::MEDIA_DATE_TRASHED, value)) {
        return E_DO_NOT_NEDD_SEND_NOTIFY;
    }

    value.GetLong(trashDate);

    string prefix;
    if (cmd.GetOprnObject() == OperationObject::FILESYSTEM_PHOTO) {
        prefix = PhotoColumn::PHOTO_URI_PREFIX;
    } else if (cmd.GetOprnObject() == OperationObject::FILESYSTEM_AUDIO) {
        prefix = AudioColumn::AUDIO_URI_PREFIX;
    } else {
        return E_OK;
    }

    string notifyUri = MediaFileUtils::GetUriByExtrConditions(prefix, to_string(rowId), extraUri);
    shared_ptr<MediaLibraryAsyncWorker> asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    if (asyncWorker == nullptr) {
        MEDIA_ERR_LOG("Can not get asyncWorker");
        return E_ERR;
    }
    DeleteNotifyAsyncTaskData* taskData = new (std::nothrow) DeleteNotifyAsyncTaskData();
    if (taskData == nullptr) {
        MEDIA_ERR_LOG("Failed to new taskData");
        return E_ERR;
    }
    taskData->notifyUri = notifyUri;
    taskData->trashDate = trashDate;
    shared_ptr<MediaLibraryAsyncTask> notifyAsyncTask = make_shared<MediaLibraryAsyncTask>(
        UpdateAlbumsAndSendNotifyInTrash, taskData);
    if (notifyAsyncTask != nullptr) {
        asyncWorker->AddTask(notifyAsyncTask, true);
    } else {
        MEDIA_ERR_LOG("Start UpdateAlbumsAndSendNotifyInTrash failed");
    }
    return E_OK;
}

void MediaLibraryAssetOperations::SendFavoriteNotify(MediaLibraryCommand &cmd, shared_ptr<FileAsset> &fileAsset,
    const string &extraUri)
{
    ValueObject value;
    int32_t isFavorite = 0;
    if (!cmd.GetValueBucket().GetObject(PhotoColumn::MEDIA_IS_FAV, value)) {
        return;
    }
    value.GetInt(isFavorite);

    MediaLibraryRdbUtils::UpdateSystemAlbumInternal(
        MediaLibraryUnistoreManager::GetInstance().GetRdbStore(),
        { to_string(PhotoAlbumSubType::FAVORITE) });
    CHECK_AND_RETURN_LOG(fileAsset != nullptr, "fileAsset is nullptr");
    if (fileAsset->IsHidden()) {
        MediaLibraryRdbUtils::UpdateSysAlbumHiddenState(
            MediaLibraryUnistoreManager::GetInstance().GetRdbStore(),
            { to_string(PhotoAlbumSubType::FAVORITE) });
    }

    auto watch = MediaLibraryNotify::GetInstance();
    if (cmd.GetOprnObject() != OperationObject::FILESYSTEM_PHOTO) {
        return;
    }
    int favAlbumId = watch->GetAlbumIdBySubType(PhotoAlbumSubType::FAVORITE);
    if (favAlbumId <= 0) {
        return;
    }

    NotifyType type = (isFavorite) ? NotifyType::NOTIFY_ALBUM_ADD_ASSET : NotifyType::NOTIFY_ALBUM_REMOVE_ASSET;
    watch->Notify(
        MediaFileUtils::GetUriByExtrConditions(PhotoColumn::PHOTO_URI_PREFIX, to_string(fileAsset->GetId()), extraUri),
        type, favAlbumId);
}

int32_t MediaLibraryAssetOperations::SendModifyUserCommentNotify(MediaLibraryCommand &cmd, int32_t rowId,
    const string &extraUri)
{
    if (cmd.GetOprnType() != OperationType::SET_USER_COMMENT) {
        return E_DO_NOT_NEDD_SEND_NOTIFY;
    }

    auto watch = MediaLibraryNotify::GetInstance();
    watch->Notify(MediaFileUtils::GetUriByExtrConditions(PhotoColumn::PHOTO_URI_PREFIX, to_string(rowId), extraUri),
        NotifyType::NOTIFY_UPDATE);
    return E_OK;
}

int32_t MediaLibraryAssetOperations::GetAlbumIdByPredicates(const string &whereClause, const vector<string> &whereArgs)
{
    size_t pos = whereClause.find(PhotoColumn::PHOTO_OWNER_ALBUM_ID);
    if (pos == string::npos) {
        MEDIA_ERR_LOG("Predicates whereClause is invalid");
        return E_ERR;
    }
    size_t argsIndex = 0;
    for (size_t i = 0; i < pos; ++i) {
        if (whereClause[i] == '?') {
            argsIndex++;
        }
    }
    if (argsIndex > whereArgs.size() - 1) {
        MEDIA_ERR_LOG("whereArgs is invalid");
        return E_ERR;
    }
    auto albumId = whereArgs[argsIndex];
    if (MediaLibraryDataManagerUtils::IsNumber(albumId)) {
        return std::atoi(albumId.c_str());
    }
    return E_ERR;
}

void MediaLibraryAssetOperations::UpdateOwnerAlbumIdOnMove(MediaLibraryCommand &cmd,
    int32_t &targetAlbumId, int32_t &oriAlbumId)
{
    ValueObject value;
    if (!cmd.GetValueBucket().GetObject(PhotoColumn::PHOTO_OWNER_ALBUM_ID, value)) {
        return;
    }
    value.GetInt(targetAlbumId);
    auto whereClause = cmd.GetAbsRdbPredicates()->GetWhereClause();
    auto whereArgs = cmd.GetAbsRdbPredicates()->GetWhereArgs();
    oriAlbumId = GetAlbumIdByPredicates(whereClause, whereArgs);

    MediaLibraryRdbUtils::UpdateUserAlbumInternal(
        MediaLibraryUnistoreManager::GetInstance().GetRdbStore(), { to_string(targetAlbumId),
        to_string(oriAlbumId) });
    MediaLibraryRdbUtils::UpdateSourceAlbumInternal(
        MediaLibraryUnistoreManager::GetInstance().GetRdbStore(), { to_string(targetAlbumId),
        to_string(oriAlbumId) });
    MEDIA_INFO_LOG("Move Assets, ori album id is %{public}d, target album id is %{public}d", oriAlbumId, targetAlbumId);
}

int32_t MediaLibraryAssetOperations::SetPendingTrue(const shared_ptr<FileAsset> &fileAsset)
{
    // time_pending = 0, means file is created, not allowed
    // time_pending = UNCREATE_FILE_TIMEPENDING, means file is not created yet, create an empty one
    // time_pending = UNCLOSE_FILE_TIMEPENDING, means file is not close yet, set pending time
    // time_pending = UNOPEN_FILE_COMPONENT_TIMEPENDING, means file is created but not open, set pending time
    // time_pending is timestamp, update it
    int64_t timestamp = MediaFileUtils::UTCTimeSeconds();
    if (timestamp <= 0) {
        MEDIA_ERR_LOG("Get timestamp failed, timestamp:%{public}ld", (long) timestamp);
        return E_INVALID_TIMESTAMP;
    }
    if (fileAsset->GetTimePending() == 0) {
        MEDIA_ERR_LOG("fileAsset time_pending is 0, not allowed");
        return E_INVALID_VALUES;
    } else if (fileAsset->GetTimePending() == UNCREATE_FILE_TIMEPENDING) {
        int32_t errCode = CreateFileAndSetPending(fileAsset, timestamp);
        if (errCode != E_OK) {
            MEDIA_ERR_LOG("Create asset failed, id=%{public}d", fileAsset->GetId());
            return errCode;
        }
    } else if (fileAsset->GetTimePending() == UNCLOSE_FILE_TIMEPENDING ||
        fileAsset->GetTimePending() == UNOPEN_FILE_COMPONENT_TIMEPENDING ||
        fileAsset->GetTimePending() > 0) {
        int32_t errCode = SetPendingTime(fileAsset, timestamp);
        if (errCode != E_OK) {
            MEDIA_ERR_LOG("Set pending time failed, id=%{public}d", fileAsset->GetId());
            return errCode;
        }
    } else {
        MEDIA_ERR_LOG("fileAsset time_pending is invalid, time_pending:%{public}ld, id=%{public}d",
            (long) fileAsset->GetTimePending(), fileAsset->GetId());
        return E_INVALID_VALUES;
    }

    return E_OK;
}

int32_t MediaLibraryAssetOperations::SetPendingFalse(const shared_ptr<FileAsset> &fileAsset)
{
    // time_pending = 0, only return
    // time_pending = UNCREATE_FILE_TIMEPENDING, means file is not created yet, not allowed
    // time_pending = UNCLOSE_FILE_TIMEPENDING, means file is not close yet, not allowed
    // time_pending = UNOPEN_FILE_COMPONENT_TIMEPENDING, means file is created but not open, not allowed
    // time_pending is timestamp, scan and set pending time = 0
    if (fileAsset->GetTimePending() == 0) {
        return E_OK;
    } else if (fileAsset->GetTimePending() == UNCREATE_FILE_TIMEPENDING) {
        MEDIA_ERR_LOG("file is not created yet, not allowed, id=%{public}d", fileAsset->GetId());
        return E_INVALID_VALUES;
    } else if (fileAsset->GetTimePending() == UNCLOSE_FILE_TIMEPENDING) {
        MEDIA_ERR_LOG("file is not close yet, not allowed, id=%{public}d", fileAsset->GetId());
        return E_INVALID_VALUES;
    } else if (fileAsset->GetTimePending() == UNOPEN_FILE_COMPONENT_TIMEPENDING) {
        MEDIA_ERR_LOG("file is created but not open, not allowed, id=%{public}d", fileAsset->GetId());
        return E_INVALID_VALUES;
    } else if (fileAsset->GetTimePending() > 0) {
        ScanFile(fileAsset->GetPath(), true, true);
    } else {
        MEDIA_ERR_LOG("fileAsset time_pending is invalid, time_pending:%{public}ld, id=%{public}d",
            (long) fileAsset->GetTimePending(), fileAsset->GetId());
        return E_INVALID_VALUES;
    }
    return E_OK;
}

int32_t MediaLibraryAssetOperations::SetPendingStatus(MediaLibraryCommand &cmd)
{
    int32_t pendingStatus = 0;
    if (!GetInt32FromValuesBucket(cmd.GetValueBucket(), MediaColumn::MEDIA_TIME_PENDING, pendingStatus)) {
        return E_INVALID_VALUES;
    }

    vector<string> columns = {
        MediaColumn::MEDIA_ID,
        MediaColumn::MEDIA_FILE_PATH,
        MediaColumn::MEDIA_TYPE,
        MediaColumn::MEDIA_TIME_PENDING
    };
    auto fileAsset = GetFileAssetFromDb(*(cmd.GetAbsRdbPredicates()), cmd.GetOprnObject(), columns);
    if (fileAsset == nullptr) {
        return E_INVALID_VALUES;
    }
    if (pendingStatus == 1) {
        return SetPendingTrue(fileAsset);
    } else if (pendingStatus == 0) {
        return SetPendingFalse(fileAsset);
    } else {
        MEDIA_ERR_LOG("pendingStatus is invalid, pendingStatus:%{public}d", pendingStatus);
        return E_INVALID_VALUES;
    }
}

static string ConvertMediaPathFromCloudPath(const string &path)
{
    // if input path is /storage/cloud/xxx, return /storage/media/local/xxx
    string mediaPath = "/storage/media/local/";
    string cloudPath = "/storage/cloud/";
    string newPath = path;
    if (newPath.find(cloudPath) != string::npos) {
        newPath.replace(newPath.find(cloudPath), cloudPath.length(), mediaPath);
    }
    return newPath;
}

int32_t MediaLibraryAssetOperations::GrantUriPermission(const string &uri, const string &bundleName,
    const string &path, bool isMovingPhoto)
{
    if (uri.empty() || path.empty()) {
        MEDIA_ERR_LOG("uri or path is empty, uri:%{private}s, path:%{private}s", uri.c_str(), path.c_str());
        return E_INVALID_VALUES;
    }
    if (bundleName.empty()) {
        MEDIA_WARN_LOG("bundleName is empty, bundleName:%{private}s", bundleName.c_str());
        return E_OK;
    }
    if (!MediaFileUtils::CreateFile(path)) {
        MEDIA_ERR_LOG("Can not create file, path: %{private}s, errno: %{public}d", path.c_str(), errno);
        return E_HAS_FS_ERROR;
    }

    if (isMovingPhoto && !MediaFileUtils::CreateFile(MediaFileUtils::GetMovingPhotoVideoPath(path))) {
        MEDIA_ERR_LOG("Failed to create video of moving photo, errno: %{public}d", errno);
        return E_HAS_FS_ERROR;
    }

    return E_OK;
}

bool MediaLibraryAssetOperations::GetInt32FromValuesBucket(const NativeRdb::ValuesBucket &values,
    const std::string &column, int32_t &value)
{
    ValueObject valueObject;
    if (values.GetObject(column, valueObject)) {
        valueObject.GetInt(value);
    } else {
        return false;
    }
    return true;
}

std::string MediaLibraryAssetOperations::CreateExtUriForV10Asset(FileAsset &fileAsset)
{
    const std::string &filePath = fileAsset.GetPath();
    const std::string &displayName = fileAsset.GetDisplayName();
    auto mediaType = fileAsset.GetMediaType();
    if (filePath.empty() || displayName.empty() || mediaType < 0) {
        MEDIA_ERR_LOG("param invalid, filePath %{private}s or displayName %{private}s invalid failed.",
            filePath.c_str(), displayName.c_str());
        return "";
    }

    string extrUri = MediaFileUtils::GetExtraUri(displayName, filePath);
    return MediaFileUtils::GetUriByExtrConditions(ML_FILE_URI_PREFIX + MediaFileUri::GetMediaTypeUri(mediaType,
        MEDIA_API_VERSION_V10) + "/", to_string(fileAsset.GetId()), extrUri);
}

bool MediaLibraryAssetOperations::GetStringFromValuesBucket(const NativeRdb::ValuesBucket &values,
    const std::string &column, string &value)
{
    ValueObject valueObject;
    if (values.GetObject(column, valueObject)) {
        valueObject.GetString(value);
    } else {
        return false;
    }
    return true;
}

int32_t MediaLibraryAssetOperations::CreateAssetUniqueId(int32_t type,
    std::shared_ptr<TransactionOperations> trans)
{
    string typeString;
    switch (type) {
        case MediaType::MEDIA_TYPE_IMAGE:
            typeString += IMAGE_ASSET_TYPE;
            break;
        case MediaType::MEDIA_TYPE_VIDEO:
            typeString += VIDEO_ASSET_TYPE;
            break;
        case MediaType::MEDIA_TYPE_AUDIO:
            typeString += AUDIO_ASSET_TYPE;
            break;
        default:
            MEDIA_ERR_LOG("This type %{public}d can not get unique id", type);
            return E_INVALID_VALUES;
    }

    const string updateSql = "UPDATE " + ASSET_UNIQUE_NUMBER_TABLE + " SET " + UNIQUE_NUMBER +
        "=" + UNIQUE_NUMBER + "+1" " WHERE " + ASSET_MEDIA_TYPE + "='" + typeString + "';";
    const string querySql = "SELECT " + UNIQUE_NUMBER + " FROM " + ASSET_UNIQUE_NUMBER_TABLE +
        " WHERE " + ASSET_MEDIA_TYPE + "='" + typeString + "';";

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        return E_HAS_DB_ERROR;
    }
    lock_guard<mutex> lock(g_uniqueNumberLock);
    int32_t errCode;
    if (trans == nullptr) {
        errCode = rdbStore->ExecuteSql(updateSql);
    } else {
        errCode = trans->ExecuteSql(updateSql);
    }
    if (errCode < 0) {
        MEDIA_ERR_LOG("execute update unique number failed, ret=%{public}d", errCode);
        return errCode;
    }

    auto resultSet = rdbStore->QuerySql(querySql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return E_HAS_DB_ERROR;
    }
    return GetInt32Val(UNIQUE_NUMBER, resultSet);
}

int32_t MediaLibraryAssetOperations::CreateAssetRealName(int32_t fileId, int32_t mediaType,
    const string &extension, string &name)
{
    string fileNumStr = to_string(fileId);
    if (fileId <= ASSET_MAX_COMPLEMENT_ID) {
        size_t fileIdLen = fileNumStr.length();
        fileNumStr = ("00" + fileNumStr).substr(fileIdLen - 1);
    }

    string mediaTypeStr;
    switch (mediaType) {
        case MediaType::MEDIA_TYPE_IMAGE:
            mediaTypeStr = DEFAULT_IMAGE_NAME;
            break;
        case MediaType::MEDIA_TYPE_VIDEO:
            mediaTypeStr = DEFAULT_VIDEO_NAME;
            break;
        case MediaType::MEDIA_TYPE_AUDIO:
            mediaTypeStr = DEFAULT_AUDIO_NAME;
            break;
        default:
            MEDIA_ERR_LOG("This mediatype %{public}d can not get real name", mediaType);
            return E_INVALID_VALUES;
    }

    static const int32_t CONFLICT_TIME = 100;
    name = mediaTypeStr + to_string(MediaFileUtils::UTCTimeSeconds() + CONFLICT_TIME) + "_" +
        fileNumStr + "." + extension;
    return E_OK;
}

static inline int32_t PrepareAssetDir(const string &dirPath)
{
    CHECK_AND_RETURN_RET(!dirPath.empty(), E_INVALID_PATH);
    if (!MediaFileUtils::IsFileExists(dirPath)) {
        bool ret = MediaFileUtils::CreateDirectory(dirPath);
        CHECK_AND_RETURN_RET_LOG(ret, E_CHECK_DIR_FAIL, "Create Dir Failed! dirPath=%{private}s",
            dirPath.c_str());
    }
    return E_OK;
}

int32_t MediaLibraryAssetOperations::CreateAssetPathById(int32_t fileId, int32_t mediaType,
    const string &extension, string &filePath)
{
    string mediaDirPath;
    GetAssetRootDir(mediaType, mediaDirPath);
    if (mediaDirPath.empty()) {
        return E_INVALID_VALUES;
    }

    int32_t bucketNum = 0;
    int32_t errCode = MediaFileUri::CreateAssetBucket(fileId, bucketNum);
    if (errCode != E_OK) {
        return errCode;
    }

    string realName;
    errCode = CreateAssetRealName(fileId, mediaType, extension, realName);
    if (errCode != E_OK) {
        return errCode;
    }

    string dirPath = ROOT_MEDIA_DIR + mediaDirPath + to_string(bucketNum);
    errCode = PrepareAssetDir(dirPath);
    if (errCode != E_OK) {
        return errCode;
    }

    filePath = dirPath + "/" + realName;
    return E_OK;
}

const std::unordered_map<std::string, std::vector<VerifyFunction>>
    AssetInputParamVerification::UPDATE_VERIFY_PARAM_MAP = {
    { MediaColumn::MEDIA_ID, { Forbidden } },
    { MediaColumn::MEDIA_FILE_PATH, { Forbidden } },
    { MediaColumn::MEDIA_SIZE, { Forbidden } },
    { MediaColumn::MEDIA_TITLE, { IsStringNotNull } },
    { MediaColumn::MEDIA_NAME, { IsStringNotNull } },
    { MediaColumn::MEDIA_TYPE, { Forbidden } },
    { MediaColumn::MEDIA_MIME_TYPE, { Forbidden } },
    { MediaColumn::MEDIA_OWNER_PACKAGE, { Forbidden } },
    { MediaColumn::MEDIA_OWNER_APPID, { Forbidden } },
    { MediaColumn::MEDIA_PACKAGE_NAME, { Forbidden } },
    { MediaColumn::MEDIA_DEVICE_NAME, { Forbidden } },
    { MediaColumn::MEDIA_DATE_MODIFIED, { Forbidden } },
    { MediaColumn::MEDIA_DATE_ADDED, { Forbidden } },
    { MediaColumn::MEDIA_DATE_TAKEN, { Forbidden } },
    { MediaColumn::MEDIA_DURATION, { Forbidden } },
    { MediaColumn::MEDIA_TIME_PENDING, { IsInt64, IsUniqueValue } },
    { MediaColumn::MEDIA_IS_FAV, { IsBool, IsUniqueValue } },
    { MediaColumn::MEDIA_DATE_TRASHED, { IsInt64, IsUniqueValue } },
    { MediaColumn::MEDIA_DATE_DELETED, { IsInt64, IsUniqueValue } },
    { MediaColumn::MEDIA_HIDDEN, { IsBool, IsUniqueValue } },
    { MediaColumn::MEDIA_PARENT_ID, { IsInt64, IsBelowApi9 } },
    { MediaColumn::MEDIA_RELATIVE_PATH, { IsString, IsBelowApi9 } },
    { MediaColumn::MEDIA_VIRTURL_PATH, { Forbidden } },
    { PhotoColumn::PHOTO_ORIENTATION, { IsInt64 } },
    { PhotoColumn::PHOTO_LATITUDE, { Forbidden } },
    { PhotoColumn::PHOTO_LONGITUDE, { Forbidden } },
    { PhotoColumn::PHOTO_HEIGHT, { Forbidden } },
    { PhotoColumn::PHOTO_WIDTH, { Forbidden } },
    { PhotoColumn::PHOTO_LCD_VISIT_TIME, { IsInt64 } },
    { PhotoColumn::PHOTO_EDIT_TIME, { IsInt64 } },
    { AudioColumn::AUDIO_ALBUM, { Forbidden } },
    { AudioColumn::AUDIO_ARTIST, { Forbidden } },
    { PhotoColumn::CAMERA_SHOT_KEY, { IsString } },
    { PhotoColumn::PHOTO_USER_COMMENT, { IsString } },
    { PhotoColumn::PHOTO_ID, { IsString } },
    { PhotoColumn::PHOTO_QUALITY, { IsInt32 } },
    { PhotoColumn::PHOTO_FIRST_VISIT_TIME, { IsInt64 } },
    { PhotoColumn::PHOTO_DEFERRED_PROC_TYPE, { IsInt32 } },
    { PhotoColumn::PHOTO_SUBTYPE, { IsInt32 } },
    { PhotoColumn::MOVING_PHOTO_EFFECT_MODE, { IsInt32 } },
    { PhotoColumn::PHOTO_COVER_POSITION, { IsInt64 } },
    { PhotoColumn::PHOTO_IS_TEMP, { IsBool } },
    { PhotoColumn::PHOTO_DIRTY, { IsInt32 } },
    { PhotoColumn::PHOTO_BURST_COVER_LEVEL, { IsInt32 } },
    { PhotoColumn::PHOTO_BURST_KEY, { IsString } },
    { PhotoColumn::PHOTO_CE_AVAILABLE, { IsInt32 } },
    { PhotoColumn::PHOTO_DETAIL_TIME, { IsStringNotNull } },
    { PhotoColumn::PHOTO_OWNER_ALBUM_ID, { IsInt32 } },
    { PhotoColumn::SUPPORTED_WATERMARK_TYPE, { IsInt32 } },
};

bool AssetInputParamVerification::CheckParamForUpdate(MediaLibraryCommand &cmd)
{
    ValuesBucket &values = cmd.GetValueBucket();
    map<string, ValueObject> valuesMap;
    values.GetAll(valuesMap);
    for (auto &iter : valuesMap) {
        if (UPDATE_VERIFY_PARAM_MAP.find(iter.first) == UPDATE_VERIFY_PARAM_MAP.end()) {
            MEDIA_ERR_LOG("param [%{private}s] is not allowed", iter.first.c_str());
            return false;
        }
        for (auto &verifyFunc : UPDATE_VERIFY_PARAM_MAP.at(iter.first)) {
            if (!verifyFunc(iter.second, cmd)) {
                MEDIA_ERR_LOG("verify param [%{private}s] failed", iter.first.c_str());
                return false;
            }
        }
    }
    return true;
}

bool AssetInputParamVerification::Forbidden(ValueObject &value, MediaLibraryCommand &cmd)
{
    return false;
}

bool AssetInputParamVerification::IsInt32(ValueObject &value, MediaLibraryCommand &cmd)
{
    if (value.GetType() == ValueObjectType::TYPE_INT) {
        return true;
    }
    return false;
}

bool AssetInputParamVerification::IsInt64(ValueObject &value, MediaLibraryCommand &cmd)
{
    if (value.GetType() == ValueObjectType::TYPE_INT) {
        return true;
    }
    return false;
}

bool AssetInputParamVerification::IsBool(ValueObject &value, MediaLibraryCommand &cmd)
{
    if (value.GetType() == ValueObjectType::TYPE_BOOL) {
        return true;
    }
    if (value.GetType() == ValueObjectType::TYPE_INT) {
        int32_t ret;
        value.GetInt(ret);
        if (ret == 0 || ret == 1) {
            return true;
        }
    }
    return false;
}

bool AssetInputParamVerification::IsString(ValueObject &value, MediaLibraryCommand &cmd)
{
    if (value.GetType() == ValueObjectType::TYPE_STRING) {
        return true;
    }
    return false;
}

bool AssetInputParamVerification::IsDouble(ValueObject &value, MediaLibraryCommand &cmd)
{
    if (value.GetType() == ValueObjectType::TYPE_DOUBLE) {
        return true;
    }
    return false;
}

bool AssetInputParamVerification::IsBelowApi9(ValueObject &value, MediaLibraryCommand &cmd)
{
    if (cmd.GetApi() == MediaLibraryApi::API_OLD) {
        return true;
    }
    return false;
}

bool AssetInputParamVerification::IsStringNotNull(ValueObject &value, MediaLibraryCommand &cmd)
{
    if (value.GetType() != ValueObjectType::TYPE_STRING) {
        return false;
    }
    string str;
    value.GetString(str);
    if (str.empty()) {
        return false;
    }
    return true;
}

bool AssetInputParamVerification::IsUniqueValue(ValueObject &value, MediaLibraryCommand &cmd)
{
    // whether this is the unique value in ValuesBucket
    map<string, ValueObject> valuesMap;
    cmd.GetValueBucket().GetAll(valuesMap);
    if (valuesMap.size() != 1) {
        return false;
    }
    return true;
}

static void CreateThumbnailFileScaned(const string &uri, const string &path, bool isSync)
{
    if (ThumbnailService::GetInstance() == nullptr) {
        return;
    }
    if (!uri.empty()) {
        int32_t err = ThumbnailService::GetInstance()->CreateThumbnailFileScaned(uri, path, isSync);
        if (err != E_SUCCESS) {
            MEDIA_ERR_LOG("ThumbnailService CreateThumbnailFileScaned failed : %{public}d", err);
        }
    }
}

int32_t MediaLibraryAssetOperations::ScanAssetCallback::OnScanFinished(const int32_t status,
    const string &uri, const string &path)
{
    if (status == E_SCANNED) {
        MEDIA_DEBUG_LOG("Asset is scannned");
        return E_OK;
    } else if (status != E_OK) {
        MEDIA_ERR_LOG("Scan is failed, status = %{public}d, skip create thumbnail", status);
        return status;
    }

    string fileId = MediaFileUtils::GetIdFromUri(uri);
    int32_t type = MediaFileUtils::GetMediaType(path);
    if (this->isInvalidateThumb) {
        InvalidateThumbnail(fileId, type);
    }
    CreateThumbnailFileScaned(uri, path, this->isCreateThumbSync);
    string livePhotoCachePath = MovingPhotoFileUtils::GetLivePhotoCachePath(path);
    if (MediaFileUtils::IsFileExists(livePhotoCachePath)) {
        (void)MediaFileUtils::DeleteFile(livePhotoCachePath);
    }
    return E_OK;
}

static void DeleteFiles(AsyncTaskData *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("DeleteFiles");
    if (data == nullptr) {
        return;
    }
    auto *taskData = static_cast<DeleteFilesTask *>(data);
    MediaLibraryRdbUtils::UpdateSystemAlbumInternal(
        MediaLibraryUnistoreManager::GetInstance().GetRdbStore(), { to_string(PhotoAlbumSubType::TRASH) });

    DfxManager::GetInstance()->HandleDeleteBehavior(DfxType::ALBUM_DELETE_ASSETS, taskData->deleteRows_,
        taskData->notifyUris_, taskData->bundleName_);
    auto watch = MediaLibraryNotify::GetInstance();
    int trashAlbumId = watch->GetAlbumIdBySubType(PhotoAlbumSubType::TRASH);
    if (trashAlbumId <= 0) {
        MEDIA_WARN_LOG("Failed to get trash album id: %{public}d", trashAlbumId);
        return;
    }
    for (const auto &notifyUri : taskData->notifyUris_) {
        watch->Notify(MediaFileUtils::Encode(notifyUri), NotifyType::NOTIFY_ALBUM_REMOVE_ASSET, trashAlbumId);
    }

    for (size_t i = 0; i < taskData->paths_.size(); i++) {
        string filePath = taskData->paths_[i];
        if (!MediaFileUtils::DeleteFile(filePath) && (errno != ENOENT)) {
            MEDIA_WARN_LOG("Failed to delete file, errno: %{public}d, path: %{private}s", errno, filePath.c_str());
        }

        if (taskData->subTypes_[i] == static_cast<int32_t>(PhotoSubType::MOVING_PHOTO)) {
            // delete video file of moving photo
            string videoPath = MediaFileUtils::GetMovingPhotoVideoPath(filePath);
            if (!MediaFileUtils::DeleteFile(videoPath) && (errno != ENOENT)) {
                MEDIA_WARN_LOG("Failed to delete video file, errno: %{public}d, path: %{private}s", errno,
                    videoPath.c_str());
            }
        }
    }
    for (size_t i = 0; i < taskData->ids_.size(); i++) {
        ThumbnailService::GetInstance()->HasInvalidateThumbnail(
            taskData->ids_[i], taskData->table_, taskData->paths_[i], taskData->dateTakens_[i]);
    }
    if (taskData->table_ == PhotoColumn::PHOTOS_TABLE) {
        for (const auto &path : taskData->paths_) {
            MediaLibraryPhotoOperations::DeleteRevertMessage(path);
        }
    }
}

int32_t GetIdsAndPaths(const AbsRdbPredicates &predicates,
    vector<string> &outIds, vector<string> &outPaths, vector<string> &outDateTakens, vector<int32_t> &outSubTypes)
{
    vector<string> columns = {
        MediaColumn::MEDIA_ID,
        MediaColumn::MEDIA_FILE_PATH,
        MediaColumn::MEDIA_DATE_TAKEN,
        PhotoColumn::PHOTO_SUBTYPE
    };
    auto resultSet = MediaLibraryRdbStore::QueryWithFilter(predicates, columns);
    if (resultSet == nullptr) {
        return E_HAS_DB_ERROR;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        outIds.push_back(
            to_string(get<int32_t>(ResultSetUtils::GetValFromColumn(MediaColumn::MEDIA_ID, resultSet, TYPE_INT32))));
        outPaths.push_back(get<string>(ResultSetUtils::GetValFromColumn(MediaColumn::MEDIA_FILE_PATH, resultSet,
            TYPE_STRING)));
        outDateTakens.push_back(get<string>(ResultSetUtils::GetValFromColumn(MediaColumn::MEDIA_DATE_TAKEN, resultSet,
            TYPE_STRING)));
        outSubTypes.push_back(
            get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoColumn::PHOTO_SUBTYPE, resultSet, TYPE_INT32)));
    }
    return E_OK;
}

static inline int32_t DeleteDbByIds(const string &table, vector<string> &ids, const bool compatible)
{
    AbsRdbPredicates predicates(table);
    predicates.In(MediaColumn::MEDIA_ID, ids);
    if (!compatible) {
        predicates.GreaterThan(MediaColumn::MEDIA_DATE_TRASHED, to_string(0));
    }
    return MediaLibraryRdbStore::Delete(predicates);
}

/**
 * @brief Delete files permanently from system.
 *
 * @param predicates Files to delete.
 * @param isAging Whether in aging process.
 * @param compatible API8 interfaces can delete files directly without trash.
 *   true: Delete files, may including non-trashed files.
 *   false: Only delete files that were already trashed.
 * @return Return deleted rows
 */
int32_t MediaLibraryAssetOperations::DeleteFromDisk(AbsRdbPredicates &predicates,
    const bool isAging, const bool compatible)
{
    MediaLibraryTracer tracer;
    tracer.Start("DeleteFromDisk");
    vector<string> whereArgs = predicates.GetWhereArgs();
    MediaLibraryRdbStore::ReplacePredicatesUriToId(predicates);
    vector<string> agingNotifyUris;
    // Query asset uris for notify before delete.
    if (isAging) {
        MediaLibraryNotify::GetNotifyUris(predicates, agingNotifyUris);
    }
    vector<string> ids;
    vector<string> paths;
    vector<string> dateTakens;
    vector<int32_t> subTypes;
    int32_t deletedRows = 0;
    GetIdsAndPaths(predicates, ids, paths, dateTakens, subTypes);
    CHECK_AND_RETURN_RET_LOG(!ids.empty(), deletedRows, "Failed to delete files in db, ids size: 0");
    // notify deferred processing session to remove image
    MultiStagesCaptureManager::RemovePhotos(predicates, false);
    // delete cloud enhanacement task
    vector<string> photoIds;
    EnhancementManager::GetInstance().RemoveTasksInternal(ids, photoIds);
    deletedRows = DeleteDbByIds(predicates.GetTableName(), ids, compatible);
    if (deletedRows <= 0) {
        MEDIA_ERR_LOG("Failed to delete files in db, deletedRows: %{public}d, ids size: %{public}zu",
            deletedRows, ids.size());
        return deletedRows;
    }
    MEDIA_INFO_LOG("Delete files in db, deletedRows: %{public}d", deletedRows);
    auto asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    CHECK_AND_RETURN_RET_LOG(asyncWorker != nullptr, E_ERR, "Can not get asyncWorker");
    const vector<string> &notifyUris = isAging ? agingNotifyUris : whereArgs;
    string bundleName = MediaLibraryBundleManager::GetInstance()->GetClientBundleName();
    auto *taskData = new (nothrow) DeleteFilesTask(ids, paths, notifyUris, dateTakens, subTypes,
        predicates.GetTableName(), deletedRows, bundleName);
    CHECK_AND_RETURN_RET_LOG(taskData != nullptr, E_ERR, "Failed to alloc async data for Delete From Disk!");
    auto deleteFilesTask = make_shared<MediaLibraryAsyncTask>(DeleteFiles, taskData);
    CHECK_AND_RETURN_RET_LOG(deleteFilesTask != nullptr, E_ERR, "Failed to create async task for deleting files.");
    asyncWorker->AddTask(deleteFilesTask, true);
    CloudMediaAssetManager::GetInstance().SetIsThumbnailUpdate();
    return deletedRows;
}
} // namespace Media
} // namespace OHOS

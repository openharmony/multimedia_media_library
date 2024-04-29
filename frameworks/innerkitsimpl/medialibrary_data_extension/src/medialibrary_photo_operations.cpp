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

#include "medialibrary_photo_operations.h"

#include <filesystem>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>

#include "abs_shared_result_set.h"
#include "file_asset.h"
#include "iservice_registry.h"
#include "media_actively_calling_analyse.h"
#include "media_column.h"
#include "media_file_uri.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_album_operations.h"
#include "medialibrary_asset_operations.h"
#include "medialibrary_command.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_inotify.h"
#include "medialibrary_notify.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_rdb_transaction.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_tracer.h"
#include "medialibrary_type_const.h"
#include "medialibrary_uripermission_operations.h"
#include "mimetype_utils.h"
#include "multistages_capture_manager.h"
#include "photo_album_column.h"
#include "photo_map_column.h"
#include "photo_map_operations.h"
#include "rdb_predicates.h"
#include "result_set_utils.h"
#include "thumbnail_const.h"
#include "uri.h"
#include "userfile_manager_types.h"
#include "value_object.h"
#include "values_bucket.h"
#include "medialibrary_formmap_operations.h"
#include "medialibrary_vision_operations.h"
#include "dfx_manager.h"

using namespace OHOS::DataShare;
using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::RdbDataShareAdapter;

namespace OHOS {
namespace Media {
static const string ANALYSIS_HAS_DATA = "1";
shared_ptr<PhotoEditingRecord> PhotoEditingRecord::instance_ = nullptr;
mutex PhotoEditingRecord::mutex_;

int32_t MediaLibraryPhotoOperations::Create(MediaLibraryCommand &cmd)
{
    switch (cmd.GetApi()) {
        case MediaLibraryApi::API_10:
            return CreateV10(cmd);
        case MediaLibraryApi::API_OLD:
            return CreateV9(cmd);
        default:
            MEDIA_ERR_LOG("get api failed");
            return E_FAIL;
    }
}

int32_t MediaLibraryPhotoOperations::DeleteCache(MediaLibraryCommand& cmd)
{
    string uriString = cmd.GetUriStringWithoutSegment();
    if (!MediaFileUtils::StartsWith(uriString, PhotoColumn::PHOTO_CACHE_URI_PREFIX)) {
        return E_INVALID_VALUES;
    }

    string fileName = uriString.substr(PhotoColumn::PHOTO_CACHE_URI_PREFIX.size());
    CHECK_AND_RETURN_RET_LOG(MediaFileUtils::CheckDisplayName(fileName) == E_OK, E_INVALID_URI,
        "Check fileName failed, fileName=%{private}s", fileName.c_str());
    string cacheDir = GetAssetCacheDir();
    string path = cacheDir + "/" + fileName;
    if (!MediaFileUtils::DeleteFile(path)) {
        MEDIA_ERR_LOG("Delete cache file failed, errno: %{public}d, uri: %{private}s", errno, uriString.c_str());
        return E_HAS_FS_ERROR;
    }
    return E_OK;
}

int32_t MediaLibraryPhotoOperations::Delete(MediaLibraryCommand& cmd)
{
    // delete file in .cache
    if (MediaFileUtils::StartsWith(cmd.GetUri().ToString(), PhotoColumn::PHOTO_CACHE_URI_PREFIX)) {
        return DeleteCache(cmd);
    }

    string fileId = cmd.GetOprnFileId();
    vector<string> columns = {
        PhotoColumn::MEDIA_ID,
        PhotoColumn::MEDIA_FILE_PATH,
        PhotoColumn::MEDIA_RELATIVE_PATH,
        PhotoColumn::MEDIA_TYPE
    };
    shared_ptr<FileAsset> fileAsset = GetFileAssetFromDb(*(cmd.GetAbsRdbPredicates()),
        cmd.GetOprnObject(), columns);
    CHECK_AND_RETURN_RET_LOG(fileAsset != nullptr, E_INVALID_FILEID, "Get fileAsset failed, fileId: %{private}s",
        fileId.c_str());
    int32_t deleteRow = DeletePhoto(fileAsset, cmd.GetApi());
    CHECK_AND_RETURN_RET_LOG(deleteRow >= 0, deleteRow, "delete photo failed, deleteRow=%{public}d", deleteRow);

    return deleteRow;
}

static void AddQueryIndex(AbsPredicates &predicates, const vector<string> &columns)
{
    auto it = find(columns.begin(), columns.end(), MEDIA_COLUMN_COUNT);
    if (it == columns.end()) {
        return;
    }
    const string &group = predicates.GetGroup();
    if (group.empty()) {
        predicates.GroupBy({ PhotoColumn::PHOTO_DATE_DAY });
        predicates.IndexedBy(PhotoColumn::PHOTO_SCHPT_DAY_INDEX);
        return;
    }
    if (group == PhotoColumn::MEDIA_TYPE) {
        predicates.IndexedBy(PhotoColumn::PHOTO_SCHPT_MEDIA_TYPE_INDEX);
        return;
    }
    if (group == PhotoColumn::PHOTO_DATE_DAY) {
        predicates.IndexedBy(PhotoColumn::PHOTO_SCHPT_DAY_INDEX);
        return;
    }
}

static int32_t GetAlbumTypeSubTypeById(const string &albumId, PhotoAlbumType &type, PhotoAlbumSubType &subType)
{
    RdbPredicates predicates(PhotoAlbumColumns::TABLE);
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, albumId);
    vector<string> columns = { PhotoAlbumColumns::ALBUM_TYPE, PhotoAlbumColumns::ALBUM_SUBTYPE };
    auto resultSet = MediaLibraryRdbStore::Query(predicates, columns);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("album id %{private}s is not exist", albumId.c_str());
        return E_INVALID_ARGUMENTS;
    }
    CHECK_AND_RETURN_RET_LOG(resultSet->GoToFirstRow() == NativeRdb::E_OK, E_INVALID_ARGUMENTS,
        "album id is not exist");
    type = static_cast<PhotoAlbumType>(GetInt32Val(PhotoAlbumColumns::ALBUM_TYPE, resultSet));
    subType = static_cast<PhotoAlbumSubType>(GetInt32Val(PhotoAlbumColumns::ALBUM_SUBTYPE, resultSet));
    return E_SUCCESS;
}

static int32_t GetPredicatesByAlbumId(const string &albumId, RdbPredicates &predicates)
{
    PhotoAlbumType type;
    PhotoAlbumSubType subType;
    CHECK_AND_RETURN_RET_LOG(GetAlbumTypeSubTypeById(albumId, type, subType) == E_SUCCESS, E_INVALID_ARGUMENTS,
        "invalid album uri");

    if ((!PhotoAlbum::CheckPhotoAlbumType(type)) || (!PhotoAlbum::CheckPhotoAlbumSubType(subType))) {
        MEDIA_ERR_LOG("album id %{private}s type:%d subtype:%d", albumId.c_str(), type, subType);
        return E_INVALID_ARGUMENTS;
    }

    if (PhotoAlbum::IsUserPhotoAlbum(type, subType)) {
        PhotoAlbumColumns::GetUserAlbumPredicates(stoi(albumId), predicates, false);
        return E_SUCCESS;
    }

    if (PhotoAlbum::IsSourceAlbum(type, subType)) {
        PhotoAlbumColumns::GetSourceAlbumPredicates(stoi(albumId), predicates, false);
        return E_SUCCESS;
    }

    if ((type != PhotoAlbumType::SYSTEM) || (subType == PhotoAlbumSubType::USER_GENERIC) ||
        (subType == PhotoAlbumSubType::ANY)) {
        MEDIA_ERR_LOG("album id %{private}s type:%d subtype:%d", albumId.c_str(), type, subType);
        return E_INVALID_ARGUMENTS;
    }
    PhotoAlbumColumns::GetSystemAlbumPredicates(subType, predicates, false);
    return E_SUCCESS;
}

static bool GetValidOrderClause(const DataSharePredicates &predicate, string &clause)
{
    constexpr int32_t FIELD_IDX = 0;
    vector<OperationItem> operations;
    const auto &items = predicate.GetOperationList();
    int32_t count = 0;
    clause = "ROW_NUMBER() OVER (ORDER BY ";
    for (const auto &item : items) {
        if (item.operation == ORDER_BY_ASC) {
            count++;
            clause += static_cast<string>(item.GetSingle(FIELD_IDX)) + " ASC) as " + PHOTO_INDEX;
        } else if (item.operation == ORDER_BY_DESC) {
            count++;
            clause += static_cast<string>(item.GetSingle(FIELD_IDX)) + " DESC) as " + PHOTO_INDEX;
        }
    }

    // only support orderby with one item
    return (count == 1);
}

static shared_ptr<NativeRdb::ResultSet> HandleAlbumIndexOfUri(const vector<string> &columns, const string &photoId,
    const string &albumId)
{
    RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    CHECK_AND_RETURN_RET_LOG(GetPredicatesByAlbumId(albumId, predicates) == E_SUCCESS, nullptr, "invalid album uri");
    return MediaLibraryRdbStore::GetIndexOfUri(predicates, columns, photoId);
}

static shared_ptr<NativeRdb::ResultSet> HandleIndexOfUri(MediaLibraryCommand &cmd, RdbPredicates &predicates,
    const string &photoId, const string &albumId)
{
    string orderClause;
    CHECK_AND_RETURN_RET_LOG(GetValidOrderClause(cmd.GetDataSharePred(), orderClause), nullptr, "invalid orderby");
    vector<string> columns;
    columns.push_back(orderClause);
    columns.push_back(MediaColumn::MEDIA_ID);
    if (!albumId.empty()) {
        return HandleAlbumIndexOfUri(columns, photoId, albumId);
    } else {
        predicates.And()->EqualTo(
            PhotoColumn::PHOTO_SYNC_STATUS, std::to_string(static_cast<int32_t>(SyncStatusType::TYPE_VISIBLE)));
        predicates.And()->EqualTo(
            PhotoColumn::PHOTO_CLEAN_FLAG, std::to_string(static_cast<int32_t>(CleanType::TYPE_NOT_CLEAN)));
        return MediaLibraryRdbStore::GetIndexOfUri(predicates, columns, photoId);
    }
}

static shared_ptr<NativeRdb::ResultSet> HandleAnalysisIndex(MediaLibraryCommand &cmd,
    const string &photoId, const string &albumId)
{
    string orderClause;
    CHECK_AND_RETURN_RET_LOG(GetValidOrderClause(cmd.GetDataSharePred(), orderClause), nullptr, "invalid orderby");
    CHECK_AND_RETURN_RET_LOG(albumId.size() > 0, nullptr, "null albumId");
    RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    PhotoAlbumColumns::GetAnalysisAlbumPredicates(stoi(albumId), predicates, false);
    vector<string> columns;
    columns.push_back(orderClause);
    columns.push_back(MediaColumn::MEDIA_ID);
    return MediaLibraryRdbStore::GetIndexOfUri(predicates, columns, photoId);
}

shared_ptr<NativeRdb::ResultSet> MediaLibraryPhotoOperations::Query(
    MediaLibraryCommand &cmd, const vector<string> &columns)
{
    RdbPredicates predicates = RdbUtils::ToPredicates(cmd.GetDataSharePred(), PhotoColumn::PHOTOS_TABLE);
    if (cmd.GetOprnType() == OperationType::INDEX || cmd.GetOprnType() == OperationType::ANALYSIS_INDEX) {
        constexpr int32_t COLUMN_SIZE = 2;
        CHECK_AND_RETURN_RET_LOG(columns.size() >= COLUMN_SIZE, nullptr, "invalid id param");
        constexpr int32_t PHOTO_ID_INDEX = 0;
        constexpr int32_t ALBUM_ID_INDEX = 1;
        string photoId = columns[PHOTO_ID_INDEX];
        string albumId;
        if (!columns[ALBUM_ID_INDEX].empty()) {
            albumId = columns[ALBUM_ID_INDEX];
        }
        if (cmd.GetOprnType() == OperationType::ANALYSIS_INDEX) {
            return HandleAnalysisIndex(cmd, photoId, albumId);
        }
        return HandleIndexOfUri(cmd, predicates, photoId, albumId);
    }
    AddQueryIndex(predicates, columns);
    return MediaLibraryRdbStore::Query(predicates, columns);
}

int32_t MediaLibraryPhotoOperations::Update(MediaLibraryCommand &cmd)
{
    switch (cmd.GetApi()) {
        case MediaLibraryApi::API_10:
            return UpdateV10(cmd);
        case MediaLibraryApi::API_OLD:
            return UpdateV9(cmd);
        default:
            MEDIA_ERR_LOG("get api failed");
            return E_FAIL;
    }

    return E_OK;
}

const static vector<string> PHOTO_COLUMN_VECTOR = {
    PhotoColumn::MEDIA_FILE_PATH,
    PhotoColumn::MEDIA_TYPE,
    PhotoColumn::MEDIA_TIME_PENDING,
    PhotoColumn::PHOTO_SUBTYPE,
};

int32_t MediaLibraryPhotoOperations::Open(MediaLibraryCommand &cmd, const string &mode)
{
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryPhotoOperations::Open");

    bool isCacheOperation = false;
    int32_t errCode = OpenCache(cmd, mode, isCacheOperation);
    if (errCode != E_OK || isCacheOperation) {
        return errCode;
    }
    bool isSkipEdit = true;
    errCode = OpenEditOperation(cmd, isSkipEdit);
    if (errCode != E_OK || !isSkipEdit) {
        return errCode;
    }
    string uriString = cmd.GetUriStringWithoutSegment();
    string id = MediaFileUtils::GetIdFromUri(uriString);
    if (uriString.empty() || (!MediaLibraryDataManagerUtils::IsNumber(id))) {
        return E_INVALID_URI;
    }
    string pendingStatus = cmd.GetQuerySetParam(MediaColumn::MEDIA_TIME_PENDING);
    shared_ptr<FileAsset> fileAsset = GetFileAssetByUri(uriString, true,  PHOTO_COLUMN_VECTOR, pendingStatus);
    if (fileAsset == nullptr) {
        MEDIA_ERR_LOG("Get FileAsset From Uri Failed, uri:%{public}s", uriString.c_str());
        return E_INVALID_URI;
    }

    bool isMovingPhotoVideo = false;
    string movingPhotoOprnKey = cmd.GetQuerySetParam(MEDIA_MOVING_PHOTO_OPRN_KEYWORD);
    if (movingPhotoOprnKey == OPEN_MOVING_PHOTO_VIDEO) {
        CHECK_AND_RETURN_RET_LOG(
            fileAsset->GetPhotoSubType() == static_cast<int32_t>(PhotoSubType::MOVING_PHOTO), E_INVALID_VALUES,
            "Non-moving photo is requesting moving photo operation, file id: %{public}s, actual subtype: %{public}d",
            id.c_str(), fileAsset->GetPhotoSubType());
        fileAsset->SetPath(MediaFileUtils::GetMovingPhotoVideoPath(fileAsset->GetPath()));
        isMovingPhotoVideo = true;
    }

    if (cmd.GetTableName() == PhotoColumn::PHOTOS_TABLE) {
        int32_t changedRows = 0;
        cmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::MEDIA_ID, id);
        changedRows = MediaLibraryRdbStore::UpdateLastVisitTime(cmd, changedRows);
        if (changedRows <= 0) {
            MEDIA_ERR_LOG("update lastVisitTime Failed, changedRows = %{public}d.", changedRows);
        }
    }
    if (uriString.find(PhotoColumn::PHOTO_URI_PREFIX) != string::npos) {
        return OpenAsset(fileAsset, mode, MediaLibraryApi::API_10, isMovingPhotoVideo);
    }
    return OpenAsset(fileAsset, mode, cmd.GetApi());
}

int32_t MediaLibraryPhotoOperations::Close(MediaLibraryCommand &cmd)
{
    const ValuesBucket &values = cmd.GetValueBucket();
    string uriString;
    if (!GetStringFromValuesBucket(values, MEDIA_DATA_DB_URI, uriString)) {
        return E_INVALID_VALUES;
    }
    string pendingStatus = cmd.GetQuerySetParam(MediaColumn::MEDIA_TIME_PENDING);

    shared_ptr<FileAsset> fileAsset = GetFileAssetByUri(uriString, true, PHOTO_COLUMN_VECTOR, pendingStatus);
    if (fileAsset == nullptr) {
        MEDIA_ERR_LOG("Get FileAsset From Uri Failed, uri:%{public}s", uriString.c_str());
        return E_INVALID_URI;
    }

    int32_t isSync = 0;
    int32_t errCode = 0;
    if (GetInt32FromValuesBucket(cmd.GetValueBucket(), CLOSE_CREATE_THUMB_STATUS, isSync) &&
        isSync == CREATE_THUMB_SYNC_STATUS) {
        errCode = CloseAsset(fileAsset, true);
    } else {
        errCode = CloseAsset(fileAsset, false);
    }
    return errCode;
}

static inline void SetPhotoTypeByRelativePath(const string &relativePath, FileAsset &fileAsset)
{
    int32_t subType = static_cast<int32_t>(PhotoSubType::DEFAULT);
    if (relativePath.compare(CAMERA_PATH) == 0) {
        subType = static_cast<int32_t>(PhotoSubType::CAMERA);
    } else if (relativePath.compare(SCREEN_RECORD_PATH) == 0 ||
        relativePath.compare(SCREEN_SHOT_PATH) == 0) {
        subType = static_cast<int32_t>(PhotoSubType::SCREENSHOT);
    }

    fileAsset.SetPhotoSubType(subType);
}

static inline void SetPhotoSubTypeFromCmd(MediaLibraryCommand &cmd, FileAsset &fileAsset)
{
    int32_t subType = static_cast<int32_t>(PhotoSubType::DEFAULT);
    ValueObject value;
    if (cmd.GetValueBucket().GetObject(PhotoColumn::PHOTO_SUBTYPE, value)) {
        value.GetInt(subType);
    }
    fileAsset.SetPhotoSubType(subType);
}

static inline void SetCameraShotKeyFromCmd(MediaLibraryCommand &cmd, FileAsset &fileAsset)
{
    string cameraShotKey;
    ValueObject value;
    if (cmd.GetValueBucket().GetObject(PhotoColumn::CAMERA_SHOT_KEY, value)) {
        value.GetString(cameraShotKey);
    }
    fileAsset.SetCameraShotKey(cameraShotKey);
}

int32_t MediaLibraryPhotoOperations::CreateV9(MediaLibraryCommand& cmd)
{
    FileAsset fileAsset;
    ValuesBucket &values = cmd.GetValueBucket();

    string displayName;
    CHECK_AND_RETURN_RET(GetStringFromValuesBucket(values, PhotoColumn::MEDIA_NAME, displayName),
        E_HAS_DB_ERROR);
    fileAsset.SetDisplayName(displayName);

    string relativePath;
    CHECK_AND_RETURN_RET(GetStringFromValuesBucket(values, PhotoColumn::MEDIA_RELATIVE_PATH, relativePath),
        E_HAS_DB_ERROR);
    fileAsset.SetRelativePath(relativePath);
    MediaFileUtils::FormatRelativePath(relativePath);

    int32_t mediaType = 0;
    CHECK_AND_RETURN_RET(GetInt32FromValuesBucket(values, PhotoColumn::MEDIA_TYPE, mediaType),
        E_HAS_DB_ERROR);
    fileAsset.SetMediaType(static_cast<MediaType>(mediaType));

    int32_t errCode = CheckRelativePathWithType(relativePath, mediaType);
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "Failed to Check RelativePath and Extention, "
        "relativePath=%{private}s, mediaType=%{public}d", relativePath.c_str(), mediaType);
    SetPhotoTypeByRelativePath(relativePath, fileAsset);
    errCode = CheckDisplayNameWithType(displayName, mediaType);
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "Failed to Check Dir and Extention, "
        "displayName=%{private}s, mediaType=%{public}d", displayName.c_str(), mediaType);

    TransactionOperations transactionOprn(MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw());
    errCode = transactionOprn.Start();
    if (errCode != E_OK) {
        return errCode;
    }

    errCode = SetAssetPathInCreate(fileAsset);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("Failed to Solve FileAsset Path and Name, displayName=%{private}s", displayName.c_str());
        return errCode;
    }

    int32_t outRow = InsertAssetInDb(cmd, fileAsset);
    if (outRow <= 0) {
        MEDIA_ERR_LOG("insert file in db failed, error = %{public}d", outRow);
        return E_HAS_DB_ERROR;
    }
    transactionOprn.Finish();
    return outRow;
}

void PhotoMapAddAsset(const int &albumId, const string &assetId, const string &extrUri)
{
    static const string INSERT_MAP_SQL = "INSERT INTO " + PhotoMap::TABLE +
        " (" + PhotoMap::ALBUM_ID + ", " + PhotoMap::ASSET_ID + ") " +
        "SELECT ?, ? WHERE " +
        "(NOT EXISTS (SELECT * FROM " + PhotoMap::TABLE + " WHERE " +
            PhotoMap::ALBUM_ID + " = ? AND " + PhotoMap::ASSET_ID + " = ?)) " +
        "AND (EXISTS (SELECT " + MediaColumn::MEDIA_ID + " FROM " + PhotoColumn::PHOTOS_TABLE + " WHERE " +
            MediaColumn::MEDIA_ID + " = ?)) " +
        "AND (EXISTS (SELECT " + PhotoAlbumColumns::ALBUM_ID + " FROM " + PhotoAlbumColumns::TABLE +
            " WHERE " + PhotoAlbumColumns::ALBUM_ID + " = ? AND " + PhotoAlbumColumns::ALBUM_TYPE + " = ? AND " +
            PhotoAlbumColumns::ALBUM_SUBTYPE + " = ?));";

    vector<ValueObject> bindArgs = { albumId, assetId, albumId, assetId, assetId, albumId, PhotoAlbumType::USER,
        PhotoAlbumSubType::USER_GENERIC };
    int errCode =  MediaLibraryRdbStore::ExecuteForLastInsertedRowId(INSERT_MAP_SQL, bindArgs);
    auto watch = MediaLibraryNotify::GetInstance();
    if (errCode > 0) {
        watch->Notify(MediaFileUtils::GetUriByExtrConditions(PhotoColumn::PHOTO_URI_PREFIX, assetId, extrUri),
            NotifyType::NOTIFY_ALBUM_ADD_ASSET, albumId);
    }
}

void MediaLibraryPhotoOperations::SolvePhotoAlbumInCreate(MediaLibraryCommand &cmd, FileAsset &fileAsset)
{
    ValuesBucket &values = cmd.GetValueBucket();
    string albumUri;
    GetStringFromValuesBucket(values, MEDIA_DATA_DB_ALARM_URI, albumUri);
    if (!albumUri.empty()) {
        PhotoMapAddAsset(stoi(MediaFileUtils::GetIdFromUri(albumUri)), to_string(fileAsset.GetId()),
            MediaFileUtils::GetExtraUri(fileAsset.GetDisplayName(), fileAsset.GetPath()));
    }
}

int32_t MediaLibraryPhotoOperations::CreateV10(MediaLibraryCommand& cmd)
{
    FileAsset fileAsset;
    ValuesBucket &values = cmd.GetValueBucket();
    string displayName;
    string extention;
    string title;
    bool isContains = false;
    bool isNeedGrant = false;
    if (GetStringFromValuesBucket(values, PhotoColumn::MEDIA_NAME, displayName)) {
        fileAsset.SetDisplayName(displayName);
        fileAsset.SetTimePending(UNCREATE_FILE_TIMEPENDING);
        isContains = true;
    } else {
        CHECK_AND_RETURN_RET(GetStringFromValuesBucket(values, ASSET_EXTENTION, extention), E_HAS_DB_ERROR);
        isNeedGrant = true;
        fileAsset.SetTimePending(UNOPEN_FILE_COMPONENT_TIMEPENDING);
        if (GetStringFromValuesBucket(values, PhotoColumn::MEDIA_TITLE, title)) {
            displayName = title + "." + extention;
            fileAsset.SetDisplayName(displayName);
            isContains = true;
        }
    }
    int32_t mediaType = 0;
    CHECK_AND_RETURN_RET(GetInt32FromValuesBucket(values, PhotoColumn::MEDIA_TYPE, mediaType), E_HAS_DB_ERROR);
    fileAsset.SetMediaType(static_cast<MediaType>(mediaType));
    SetPhotoSubTypeFromCmd(cmd, fileAsset);
    SetCameraShotKeyFromCmd(cmd, fileAsset);
    // Check rootdir and extention
    int32_t errCode = CheckWithType(isContains, displayName, extention, mediaType);
    CHECK_AND_RETURN_RET(errCode == E_OK, errCode);
    TransactionOperations transactionOprn(MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw());
    errCode = transactionOprn.Start();
    CHECK_AND_RETURN_RET(errCode == E_OK, errCode);
    errCode = isContains ? SetAssetPathInCreate(fileAsset) : SetAssetPath(fileAsset, extention);
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode,
        "Failed to Solve FileAsset Path and Name, displayName=%{private}s", displayName.c_str());
    int32_t outRow = InsertAssetInDb(cmd, fileAsset);
    CHECK_AND_RETURN_RET_LOG(outRow > 0, E_HAS_DB_ERROR, "insert file in db failed, error = %{public}d", outRow);
    fileAsset.SetId(outRow);
    SolvePhotoAlbumInCreate(cmd, fileAsset);
    transactionOprn.Finish();
    string fileUri = CreateExtUriForV10Asset(fileAsset);
    if (isNeedGrant) {
        bool isMovingPhoto = fileAsset.GetPhotoSubType() == static_cast<int32_t>(PhotoSubType::MOVING_PHOTO);
        int32_t ret = GrantUriPermission(fileUri, cmd.GetBundleName(), fileAsset.GetPath(), isMovingPhoto);
        CHECK_AND_RETURN_RET(ret == E_OK, ret);
    }
    cmd.SetResult(fileUri);
    return outRow;
}

int32_t MediaLibraryPhotoOperations::DeletePhoto(const shared_ptr<FileAsset> &fileAsset, MediaLibraryApi api)
{
    string filePath = fileAsset->GetPath();
    CHECK_AND_RETURN_RET_LOG(!filePath.empty(), E_INVALID_PATH, "get file path failed");
    bool res = MediaFileUtils::DeleteFile(filePath);
    CHECK_AND_RETURN_RET_LOG(res, E_HAS_FS_ERROR, "Delete photo file failed, errno: %{public}d", errno);

    // delete thumbnail
    int32_t fileId = fileAsset->GetId();
    InvalidateThumbnail(to_string(fileId), fileAsset->GetMediaType());

    TransactionOperations transactionOprn(MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw());
    int32_t errCode = transactionOprn.Start();
    if (errCode != E_OK) {
        return errCode;
    }

    string displayName = fileAsset->GetDisplayName();
    // delete file in db
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::DELETE);
    cmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::MEDIA_ID, to_string(fileId));
    int32_t deleteRows = DeleteAssetInDb(cmd);
    if (deleteRows <= 0) {
        MEDIA_ERR_LOG("Delete photo in database failed, errCode=%{public}d", deleteRows);
        return E_HAS_DB_ERROR;
    }

    transactionOprn.Finish();
    auto watch = MediaLibraryNotify::GetInstance();
    string notifyDeleteUri =
        MediaFileUtils::GetUriByExtrConditions(PhotoColumn::PHOTO_URI_PREFIX, to_string(deleteRows),
        (api == MediaLibraryApi::API_10 ? MediaFileUtils::GetExtraUri(displayName, filePath) : ""));
    watch->Notify(notifyDeleteUri, NotifyType::NOTIFY_REMOVE);

    DeleteRevertMessage(filePath);
    return deleteRows;
}

static void TrashPhotosSendNotify(vector<string> &notifyUris)
{
    auto watch = MediaLibraryNotify::GetInstance();
    int trashAlbumId = watch->GetAlbumIdBySubType(PhotoAlbumSubType::TRASH);
    if (trashAlbumId <= 0) {
        return;
    }
    if (notifyUris.empty()) {
        return;
    }
    watch->Notify(PhotoColumn::PHOTO_URI_PREFIX, NotifyType::NOTIFY_REMOVE);
    watch->Notify(PhotoAlbumColumns::ALBUM_URI_PREFIX, NotifyType::NOTIFY_UPDATE);
    vector<int64_t> formIds;
    for (const auto &notifyUri : notifyUris) {
        MediaLibraryFormMapOperations::GetFormMapFormId(notifyUri.c_str(), formIds);
    }
    if (!formIds.empty()) {
        MediaLibraryFormMapOperations::PublishedChange("", formIds, false);
    }
}

static void ActivelyStartAnalysisService()
{
    int32_t code = MediaActivelyCallingAnalyse::ActivateServiceType::START_UPDATE_INDEX;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    MediaActivelyCallingAnalyse mediaActivelyCallingAnalyse(nullptr);
    if (!mediaActivelyCallingAnalyse.SendTransactCmd(code, data, reply, option)) {
        MEDIA_ERR_LOG("Actively Calling Analyse For update index Fail");
    }
}

int32_t MediaLibraryPhotoOperations::TrashPhotos(MediaLibraryCommand &cmd)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        return E_HAS_DB_ERROR;
    }

    NativeRdb::RdbPredicates rdbPredicate = RdbUtils::ToPredicates(cmd.GetDataSharePred(),
        PhotoColumn::PHOTOS_TABLE);
    vector<string> notifyUris = rdbPredicate.GetWhereArgs();
    MediaLibraryRdbStore::ReplacePredicatesUriToId(rdbPredicate);

    MultiStagesCaptureManager::GetInstance().RemoveImages(rdbPredicate, true);

    ValuesBucket values;
    values.Put(MediaColumn::MEDIA_DATE_TRASHED, MediaFileUtils::UTCTimeMilliSeconds());
    cmd.SetValueBucket(values);
    int32_t updatedRows = rdbStore->Update(values, rdbPredicate);
    if (updatedRows < 0) {
        MEDIA_ERR_LOG("Trash photo failed. Result %{public}d.", updatedRows);
        return E_HAS_DB_ERROR;
    }
    ActivelyStartAnalysisService();
    std::unordered_map<int32_t, int32_t>  updateResult;
    MediaLibraryRdbUtils::UpdateAllAlbums(rdbStore->GetRaw(), updateResult, notifyUris);
    if (static_cast<size_t>(updatedRows) != notifyUris.size()) {
        MEDIA_WARN_LOG("Try to notify %{public}zu items, but only %{public}d items updated.",
            notifyUris.size(), updatedRows);
    }
    TrashPhotosSendNotify(notifyUris);
    DfxManager::GetInstance()->HandleDeleteBehavior(DfxType::TRASH_PHOTO, updatedRows, updateResult,
        notifyUris);
    return updatedRows;
}

static int32_t GetHiddenState(const ValuesBucket &values)
{
    ValueObject obj;
    auto ret = values.GetObject(MediaColumn::MEDIA_HIDDEN, obj);
    if (!ret) {
        return E_INVALID_VALUES;
    }
    int32_t hiddenState = 0;
    ret = obj.GetInt(hiddenState);
    if (ret != E_OK) {
        return E_INVALID_VALUES;
    }
    return hiddenState == 0 ? 0 : 1;
}

static void SendHideNotify(vector<string> &notifyUris, const int32_t hiddenState)
{
    auto watch = MediaLibraryNotify::GetInstance();
    if (watch == nullptr) {
        return;
    }
    int hiddenAlbumId = watch->GetAlbumIdBySubType(PhotoAlbumSubType::HIDDEN);
    if (hiddenAlbumId <= 0) {
        return;
    }

    NotifyType assetNotifyType;
    NotifyType albumNotifyType;
    NotifyType hiddenAlbumNotifyType;
    if (hiddenState > 0) {
        assetNotifyType = NotifyType::NOTIFY_REMOVE;
        albumNotifyType = NotifyType::NOTIFY_ALBUM_REMOVE_ASSET;
        hiddenAlbumNotifyType = NotifyType::NOTIFY_ALBUM_ADD_ASSET;
    } else {
        assetNotifyType = NotifyType::NOTIFY_ADD;
        albumNotifyType = NotifyType::NOTIFY_ALBUM_ADD_ASSET;
        hiddenAlbumNotifyType = NotifyType::NOTIFY_ALBUM_REMOVE_ASSET;
    }
    vector<int64_t> formIds;
    for (const auto &notifyUri : notifyUris) {
        watch->Notify(notifyUri, assetNotifyType);
        watch->Notify(notifyUri, albumNotifyType, 0, true);
        watch->Notify(notifyUri, hiddenAlbumNotifyType, hiddenAlbumId);
        MediaLibraryFormMapOperations::GetFormMapFormId(notifyUri.c_str(), formIds);
    }
    if (!formIds.empty()) {
        MediaLibraryFormMapOperations::PublishedChange("", formIds, false);
    }
}

static int32_t HidePhotos(MediaLibraryCommand &cmd)
{
    int32_t hiddenState = GetHiddenState(cmd.GetValueBucket());
    if (hiddenState < 0) {
        return hiddenState;
    }

    RdbPredicates predicates = RdbUtils::ToPredicates(cmd.GetDataSharePred(), PhotoColumn::PHOTOS_TABLE);
    vector<string> notifyUris = predicates.GetWhereArgs();
    MediaLibraryRdbStore::ReplacePredicatesUriToId(predicates);
    ValuesBucket values;
    values.Put(MediaColumn::MEDIA_HIDDEN, hiddenState);
    if (predicates.GetTableName() == PhotoColumn::PHOTOS_TABLE) {
        values.PutLong(PhotoColumn::PHOTO_HIDDEN_TIME,
            hiddenState ? MediaFileUtils::UTCTimeMilliSeconds() : 0);
    }
    int32_t changedRows = MediaLibraryRdbStore::Update(values, predicates);
    if (changedRows < 0) {
        return changedRows;
    }
    ActivelyStartAnalysisService();
    MediaLibraryRdbUtils::UpdateSystemAlbumInternal(
        MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw(), {
            std::to_string(PhotoAlbumSubType::FAVORITE),
            std::to_string(PhotoAlbumSubType::VIDEO),
            std::to_string(PhotoAlbumSubType::HIDDEN),
            std::to_string(PhotoAlbumSubType::SCREENSHOT),
            std::to_string(PhotoAlbumSubType::IMAGE),
        });
    std::unordered_map<int32_t, int32_t> updateResult;
    MediaLibraryRdbUtils::UpdateUserAlbumByUri(
        MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw(), updateResult, notifyUris);
    MediaLibraryRdbUtils::UpdateSourceAlbumByUri(
        MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw(), updateResult, notifyUris);

    MediaLibraryRdbUtils::UpdateHiddenAlbumInternal(
        MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw(), updateResult);
    MediaLibraryRdbUtils::UpdateAnalysisAlbumByUri(
        MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw(), updateResult, notifyUris);
    SendHideNotify(notifyUris, hiddenState);
    return changedRows;
}

static int32_t GetFavoriteState(const ValuesBucket& values)
{
    ValueObject obj;
    bool isValid = values.GetObject(PhotoColumn::MEDIA_IS_FAV, obj);
    if (!isValid) {
        return E_INVALID_VALUES;
    }

    int32_t favoriteState = -1;
    int ret = obj.GetInt(favoriteState);
    if (ret != E_OK || (favoriteState != 0 && favoriteState != 1)) {
        return E_INVALID_VALUES;
    }
    return favoriteState;
}

static int32_t BatchSetFavorite(MediaLibraryCommand& cmd)
{
    int32_t favoriteState = GetFavoriteState(cmd.GetValueBucket());
    CHECK_AND_RETURN_RET_LOG(favoriteState >= 0, favoriteState, "Failed to get favoriteState");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_HAS_DB_ERROR, "Failed to get rdbStore");

    RdbPredicates predicates = RdbUtils::ToPredicates(cmd.GetDataSharePred(), PhotoColumn::PHOTOS_TABLE);
    vector<string> notifyUris = predicates.GetWhereArgs();
    MediaLibraryRdbStore::ReplacePredicatesUriToId(predicates);
    ValuesBucket values;
    values.Put(PhotoColumn::MEDIA_IS_FAV, favoriteState);
    int32_t updatedRows = rdbStore->Update(values, predicates);
    CHECK_AND_RETURN_RET_LOG(updatedRows >= 0, E_HAS_DB_ERROR, "Failed to set favorite, err: %{public}d", updatedRows);

    MediaLibraryRdbUtils::UpdateSystemAlbumInternal(rdbStore->GetRaw(), { to_string(PhotoAlbumSubType::FAVORITE) });
    auto watch = MediaLibraryNotify::GetInstance();
    int favAlbumId = watch->GetAlbumIdBySubType(PhotoAlbumSubType::FAVORITE);
    if (favAlbumId > 0) {
        NotifyType type = favoriteState ? NotifyType::NOTIFY_ALBUM_ADD_ASSET : NotifyType::NOTIFY_ALBUM_REMOVE_ASSET;
        for (const string& notifyUri : notifyUris) {
            watch->Notify(notifyUri, type, favAlbumId);
        }
    } else {
        MEDIA_WARN_LOG("Favorite album not found, failed to notify favorite album.");
    }

    for (const string& notifyUri : notifyUris) {
        watch->Notify(notifyUri, NotifyType::NOTIFY_UPDATE);
    }

    if (static_cast<size_t>(updatedRows) != notifyUris.size()) {
        MEDIA_WARN_LOG(
            "Try to notify %{public}zu items, but only %{public}d items updated.", notifyUris.size(), updatedRows);
    }
    return updatedRows;
}

int32_t MediaLibraryPhotoOperations::BatchSetUserComment(MediaLibraryCommand& cmd)
{
    vector<shared_ptr<FileAsset>> fileAssetVector;
    vector<string> columns = { PhotoColumn::MEDIA_ID, PhotoColumn::MEDIA_FILE_PATH,
        PhotoColumn::MEDIA_TYPE, PhotoColumn::MEDIA_NAME };
    MediaLibraryRdbStore::ReplacePredicatesUriToId(*(cmd.GetAbsRdbPredicates()));
    int32_t errCode = GetFileAssetVectorFromDb(*(cmd.GetAbsRdbPredicates()),
        OperationObject::FILESYSTEM_PHOTO, fileAssetVector, columns);
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode,
        "Failed to query file asset vector from db, errCode=%{private}d", errCode);

    for (const auto& fileAsset : fileAssetVector) {
        errCode = SetUserComment(cmd, fileAsset);
        CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "Failed to set user comment, errCode=%{private}d", errCode);
    }

    TransactionOperations transactionOprn(MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw());
    errCode = transactionOprn.Start();
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode,
        "Failed to start TransactionOperations, errCode=%{private}d", errCode);
    int32_t updateRows = UpdateFileInDb(cmd);
    if (updateRows < 0) {
        MEDIA_ERR_LOG("Update Photo in database failed, updateRows=%{public}d", updateRows);
        return updateRows;
    }
    transactionOprn.Finish();

    auto watch = MediaLibraryNotify::GetInstance();
    for (const auto& fileAsset : fileAssetVector) {
        string extraUri = MediaFileUtils::GetExtraUri(fileAsset->GetDisplayName(), fileAsset->GetPath());
        string assetUri = MediaFileUtils::GetUriByExtrConditions(
            PhotoColumn::PHOTO_URI_PREFIX, to_string(fileAsset->GetId()), extraUri);
        watch->Notify(assetUri, NotifyType::NOTIFY_UPDATE);
    }
    return updateRows;
}

int32_t MediaLibraryPhotoOperations::UpdateFileAsset(MediaLibraryCommand &cmd)
{
    vector<string> columns = {
        PhotoColumn::MEDIA_ID,
        PhotoColumn::MEDIA_FILE_PATH,
        PhotoColumn::MEDIA_TYPE,
        PhotoColumn::MEDIA_NAME
    };
    shared_ptr<FileAsset> fileAsset = GetFileAssetFromDb(*(cmd.GetAbsRdbPredicates()),
        OperationObject::FILESYSTEM_PHOTO, columns);
    if (fileAsset == nullptr) {
        return E_INVALID_VALUES;
    }

    int32_t errCode;
    if (cmd.GetOprnType() == OperationType::SET_USER_COMMENT) {
        errCode = SetUserComment(cmd, fileAsset);
        CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "Edit user comment errCode = %{private}d", errCode);
    }

    // Update if FileAsset.title or FileAsset.displayName is modified
    bool isNameChanged = false;
    errCode = UpdateFileName(cmd, fileAsset, isNameChanged);
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "Update Photo Name failed, fileName=%{private}s",
        fileAsset->GetDisplayName().c_str());

    TransactionOperations transactionOprn(MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw());
    errCode = transactionOprn.Start();
    if (errCode != E_OK) {
        return errCode;
    }

    int32_t rowId = UpdateFileInDb(cmd);
    if (rowId < 0) {
        MEDIA_ERR_LOG("Update Photo In database failed, rowId=%{public}d", rowId);
        return rowId;
    }
    transactionOprn.Finish();
    string extraUri = MediaFileUtils::GetExtraUri(fileAsset->GetDisplayName(), fileAsset->GetPath());
    errCode = SendTrashNotify(cmd, fileAsset->GetId(), extraUri);
    if (errCode == E_OK) {
        return rowId;
    }
    SendFavoriteNotify(cmd, fileAsset->GetId(), extraUri);
    SendModifyUserCommentNotify(cmd, fileAsset->GetId(), extraUri);
    auto watch = MediaLibraryNotify::GetInstance();
    watch->Notify(MediaFileUtils::GetUriByExtrConditions(PhotoColumn::PHOTO_URI_PREFIX, to_string(fileAsset->GetId()),
        extraUri), NotifyType::NOTIFY_UPDATE);
    return rowId;
}

int32_t MediaLibraryPhotoOperations::UpdateV10(MediaLibraryCommand &cmd)
{
    switch (cmd.GetOprnType()) {
        case OperationType::TRASH_PHOTO:
            return TrashPhotos(cmd);
        case OperationType::UPDATE_PENDING:
            return SetPendingStatus(cmd);
        case OperationType::HIDE:
            return HidePhotos(cmd);
        case OperationType::BATCH_UPDATE_FAV:
            return BatchSetFavorite(cmd);
        case OperationType::BATCH_UPDATE_USER_COMMENT:
            return BatchSetUserComment(cmd);
        default:
            return UpdateFileAsset(cmd);
    }
    return E_OK;
}

int32_t MediaLibraryPhotoOperations::UpdateV9(MediaLibraryCommand &cmd)
{
    vector<string> columns = {
        PhotoColumn::MEDIA_ID,
        PhotoColumn::MEDIA_FILE_PATH,
        PhotoColumn::MEDIA_TYPE,
        PhotoColumn::MEDIA_NAME,
        PhotoColumn::MEDIA_RELATIVE_PATH
    };
    shared_ptr<FileAsset> fileAsset = GetFileAssetFromDb(*(cmd.GetAbsRdbPredicates()),
        OperationObject::FILESYSTEM_PHOTO, columns);
    if (fileAsset == nullptr) {
        return E_INVALID_VALUES;
    }

    // Update if FileAsset.title or FileAsset.displayName is modified
    bool isNameChanged = false;
    int32_t errCode = UpdateFileName(cmd, fileAsset, isNameChanged);
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "Update Photo Name failed, fileName=%{private}s",
        fileAsset->GetDisplayName().c_str());
    errCode = UpdateRelativePath(cmd, fileAsset, isNameChanged);
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "Update Photo RelativePath failed, relativePath=%{private}s",
        fileAsset->GetRelativePath().c_str());
    if (isNameChanged) {
        UpdateVirtualPath(cmd, fileAsset);
    }

    TransactionOperations transactionOprn(MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw());
    errCode = transactionOprn.Start();
    if (errCode != E_OK) {
        return errCode;
    }

    int32_t rowId = UpdateFileInDb(cmd);
    if (rowId < 0) {
        MEDIA_ERR_LOG("Update Photo In database failed, rowId=%{public}d", rowId);
        return rowId;
    }
    transactionOprn.Finish();

    errCode = SendTrashNotify(cmd, fileAsset->GetId());
    if (errCode == E_OK) {
        return rowId;
    }
    SendFavoriteNotify(cmd, fileAsset->GetId());
    auto watch = MediaLibraryNotify::GetInstance();
    watch->Notify(MediaFileUtils::GetUriByExtrConditions(PhotoColumn::PHOTO_URI_PREFIX, to_string(fileAsset->GetId())),
        NotifyType::NOTIFY_UPDATE);
    return rowId;
}

int32_t MediaLibraryPhotoOperations::OpenCache(MediaLibraryCommand& cmd, const string& mode, bool& isCacheOperation)
{
    isCacheOperation = false;
    string uriString = cmd.GetUriStringWithoutSegment();
    if (!MediaFileUtils::StartsWith(uriString, PhotoColumn::PHOTO_CACHE_URI_PREFIX)) {
        return E_OK;
    }

    isCacheOperation = true;
    string fileName = uriString.substr(PhotoColumn::PHOTO_CACHE_URI_PREFIX.size());
    CHECK_AND_RETURN_RET_LOG(MediaFileUtils::CheckDisplayName(fileName) == E_OK, E_INVALID_URI,
        "Check fileName failed, fileName=%{private}s", fileName.c_str());
    MediaType mediaType = MediaFileUtils::GetMediaType(fileName);
    CHECK_AND_RETURN_RET_LOG(mediaType == MediaType::MEDIA_TYPE_IMAGE || mediaType == MediaType::MEDIA_TYPE_VIDEO,
        E_INVALID_URI, "Check mediaType failed, fileName=%{private}s, mediaType=%{public}d", fileName.c_str(),
        mediaType);

    string cacheDir = GetAssetCacheDir();
    string path = cacheDir + "/" + fileName;

    if (mode == MEDIA_FILEMODE_READONLY) {
        CHECK_AND_RETURN_RET_LOG(MediaFileUtils::IsFileExists(path), E_HAS_FS_ERROR,
            "Cache file does not exist, path=%{private}s", path.c_str());
        return OpenFileWithPrivacy(path, mode);
    }
    CHECK_AND_RETURN_RET_LOG(
        MediaFileUtils::CreateDirectory(cacheDir), E_HAS_FS_ERROR, "Cannot create dir %{private}s", cacheDir.c_str());
    CHECK_AND_RETURN_RET_LOG(MediaFileUtils::CreateAsset(path) == E_SUCCESS, E_HAS_FS_ERROR,
        "Create cache file failed, path=%{private}s", path.c_str());
    return OpenFileWithPrivacy(path, mode);
}

int32_t MediaLibraryPhotoOperations::OpenEditOperation(MediaLibraryCommand &cmd, bool &isSkip)
{
    isSkip = true;
    string operationKey = cmd.GetQuerySetParam(MEDIA_OPERN_KEYWORD);
    if (operationKey.empty()) {
        return E_OK;
    }
    if (operationKey == EDIT_DATA_REQUEST) {
        isSkip = false;
        return RequestEditData(cmd);
    } else if (operationKey == SOURCE_REQUEST) {
        isSkip = false;
        return RequestEditSource(cmd);
    } else if (operationKey == COMMIT_REQUEST) {
        isSkip = false;
        return CommitEditOpen(cmd);
    }

    return E_OK;
}

const static vector<string> EDITED_COLUMN_VECTOR = {
    PhotoColumn::MEDIA_FILE_PATH,
    PhotoColumn::PHOTO_EDIT_TIME,
    PhotoColumn::MEDIA_TIME_PENDING,
    PhotoColumn::MEDIA_DATE_TRASHED,
    PhotoColumn::PHOTO_SUBTYPE,
};

int32_t MediaLibraryPhotoOperations::RequestEditData(MediaLibraryCommand &cmd)
{
    string uriString = cmd.GetUriStringWithoutSegment();
    string id = MediaFileUtils::GetIdFromUri(uriString);
    if (uriString.empty() || (!MediaLibraryDataManagerUtils::IsNumber(id))) {
        return E_INVALID_URI;
    }

    shared_ptr<FileAsset> fileAsset = GetFileAssetFromDb(PhotoColumn::MEDIA_ID, id,
        OperationObject::FILESYSTEM_PHOTO, EDITED_COLUMN_VECTOR);
    CHECK_AND_RETURN_RET_LOG(fileAsset != nullptr, E_INVALID_URI, "Get FileAsset From Uri Failed, uri:%{public}s",
        uriString.c_str());
    CHECK_AND_RETURN_RET_LOG(fileAsset->GetTimePending() == 0, E_IS_PENDING_ERROR,
        "FileAsset is in PendingStatus %{public}ld", (long) fileAsset->GetTimePending());
    CHECK_AND_RETURN_RET_LOG(fileAsset->GetDateTrashed() == 0, E_IS_RECYCLED, "FileAsset is in recycle");

    string path = fileAsset->GetFilePath();
    CHECK_AND_RETURN_RET_LOG(!path.empty(), E_INVALID_URI, "Can not get file path, uri=%{private}s",
        uriString.c_str());

    string dataPath = GetEditDataPath(path);
    CHECK_AND_RETURN_RET_LOG(!dataPath.empty(), E_INVALID_PATH, "Get edit data path from path %{private}s failed",
        dataPath.c_str());
    if (fileAsset->GetPhotoEditTime() == 0) {
        MEDIA_INFO_LOG("File %{private}s does not have edit data", uriString.c_str());
        string dataPathDir = GetEditDataDirPath(path);
        CHECK_AND_RETURN_RET_LOG(!dataPathDir.empty(), E_INVALID_PATH,
            "Get edit data dir path from path %{private}s failed", path.c_str());
        if (!MediaFileUtils::IsDirectory(dataPathDir)) {
            CHECK_AND_RETURN_RET_LOG(MediaFileUtils::CreateDirectory(dataPathDir), E_HAS_FS_ERROR,
                "Failed to create dir %{private}s", dataPathDir.c_str());
        }

        if (!MediaFileUtils::IsFileExists(dataPath)) {
            int32_t err = MediaFileUtils::CreateAsset(dataPath);
            CHECK_AND_RETURN_RET_LOG(err == E_SUCCESS || err == E_FILE_EXIST, E_HAS_FS_ERROR,
                "Failed to create file %{private}s", dataPath.c_str());
        }
    } else {
        if (!MediaFileUtils::IsFileExists(dataPath)) {
            MEDIA_INFO_LOG("File %{public}s has edit at %{public}ld, but cannot get editdata", uriString.c_str(),
                (long)fileAsset->GetPhotoEditTime());
            return E_HAS_FS_ERROR;
        }
    }

    return OpenFileWithPrivacy(dataPath, "r");
}

int32_t MediaLibraryPhotoOperations::RequestEditSource(MediaLibraryCommand &cmd)
{
    string uriString = cmd.GetUriStringWithoutSegment();
    string id = MediaFileUtils::GetIdFromUri(uriString);
    if (uriString.empty() || (!MediaLibraryDataManagerUtils::IsNumber(id))) {
        return E_INVALID_URI;
    }
    CHECK_AND_RETURN_RET_LOG(!PhotoEditingRecord::GetInstance()->IsInRevertOperation(stoi(id)),
        E_IS_IN_COMMIT, "File %{public}s is in revert, can not request source", id.c_str());
    shared_ptr<FileAsset> fileAsset = GetFileAssetFromDb(PhotoColumn::MEDIA_ID, id,
        OperationObject::FILESYSTEM_PHOTO, EDITED_COLUMN_VECTOR);
    CHECK_AND_RETURN_RET_LOG(fileAsset != nullptr, E_INVALID_URI,
        "Get fileAsset from uri failed, uri:%{public}s", uriString.c_str());
    CHECK_AND_RETURN_RET_LOG(fileAsset->GetTimePending() == 0, E_IS_PENDING_ERROR,
        "FileAsset is in PendingStatus %{public}ld", (long) fileAsset->GetTimePending());
    CHECK_AND_RETURN_RET_LOG(fileAsset->GetDateTrashed() == 0, E_IS_RECYCLED, "FileAsset is in recycle");
    string path = fileAsset->GetFilePath();
    CHECK_AND_RETURN_RET_LOG(!path.empty(), E_INVALID_URI,
        "Can not get file path, uri=%{private}s", uriString.c_str());
    string movingPhotoVideoPath = "";
    bool isMovingPhotoVideoRequest =
        cmd.GetQuerySetParam(MEDIA_MOVING_PHOTO_OPRN_KEYWORD) == OPEN_MOVING_PHOTO_VIDEO;
    if (isMovingPhotoVideoRequest) {
        CHECK_AND_RETURN_RET_LOG(
            fileAsset->GetPhotoSubType() == static_cast<int32_t>(PhotoSubType::MOVING_PHOTO), E_INVALID_VALUES,
            "Non-moving photo requesting moving photo operation, file id: %{public}s, actual subtype: %{public}d",
            id.c_str(), fileAsset->GetPhotoSubType());
        movingPhotoVideoPath = MediaFileUtils::GetMovingPhotoVideoPath(path);
    }
    if (fileAsset->GetPhotoEditTime() == 0) {
        return OpenFileWithPrivacy(isMovingPhotoVideoRequest ? movingPhotoVideoPath : path, "r");
    }
    string sourcePath = isMovingPhotoVideoRequest ?
        MediaFileUtils::GetMovingPhotoVideoPath(GetEditDataSourcePath(path)) :
        GetEditDataSourcePath(path);
    if (sourcePath.empty() || !MediaFileUtils::IsFileExists(sourcePath)) {
        return OpenFileWithPrivacy(isMovingPhotoVideoRequest ? path : movingPhotoVideoPath, "r");
    } else {
        return OpenFileWithPrivacy(sourcePath, "r");
    }
}

int32_t MediaLibraryPhotoOperations::CommitEditOpen(MediaLibraryCommand &cmd)
{
    string uriString = cmd.GetUriStringWithoutSegment();
    string id = MediaFileUtils::GetIdFromUri(uriString);
    if (uriString.empty() || (!MediaLibraryDataManagerUtils::IsNumber(id))) {
        return E_INVALID_URI;
    }

    shared_ptr<FileAsset> fileAsset = GetFileAssetFromDb(PhotoColumn::MEDIA_ID, id,
        OperationObject::FILESYSTEM_PHOTO, EDITED_COLUMN_VECTOR);
    if (fileAsset == nullptr) {
        MEDIA_ERR_LOG("Get FileAsset From Uri Failed, uri:%{public}s", uriString.c_str());
        return E_INVALID_URI;
    }
    int32_t fileId = stoi(id);  // after MediaLibraryDataManagerUtils::IsNumber, id must be number
    if (!PhotoEditingRecord::GetInstance()->StartCommitEdit(fileId)) {
        return E_IS_IN_REVERT;
    }
    int32_t fd = CommitEditOpenExecute(fileAsset);
    if (fd < 0) {
        PhotoEditingRecord::GetInstance()->EndCommitEdit(fileId);
    }
    return fd;
}

int32_t MediaLibraryPhotoOperations::CommitEditOpenExecute(const shared_ptr<FileAsset> &fileAsset)
{
    if (fileAsset == nullptr) {
        return E_INVALID_URI;
    }
    if (fileAsset->GetTimePending() != 0) {
        MEDIA_ERR_LOG("FileAsset is in PendingStatus %{public}ld", (long) fileAsset->GetTimePending());
        return E_IS_PENDING_ERROR;
    }
    if (fileAsset->GetDateTrashed() != 0) {
        MEDIA_ERR_LOG("FileAsset is in recycle");
        return E_IS_RECYCLED;
    }
    string path = fileAsset->GetFilePath();
    if (path.empty()) {
        MEDIA_ERR_LOG("Can not get file path");
        return E_INVALID_URI;
    }
    if (fileAsset->GetPhotoEditTime() == 0) {
        string sourceDirPath = GetEditDataDirPath(path);
        CHECK_AND_RETURN_RET_LOG(!sourceDirPath.empty(), E_INVALID_URI, "Can not get edit dir path");
        CHECK_AND_RETURN_RET_LOG(MediaFileUtils::CreateDirectory(sourceDirPath), E_HAS_FS_ERROR,
            "Can not create dir %{private}s", sourceDirPath.c_str());
        string sourcePath = GetEditDataSourcePath(path);
        CHECK_AND_RETURN_RET_LOG(!sourcePath.empty(), E_INVALID_URI, "Can not get edit source path");
        if (!MediaFileUtils::IsFileExists(sourcePath)) {
            CHECK_AND_RETURN_RET_LOG(MediaFileUtils::ModifyAsset(path, sourcePath) == E_SUCCESS, E_HAS_FS_ERROR,
                "Move file failed, srcPath:%{private}s, newPath:%{private}s", path.c_str(), sourcePath.c_str());
            CHECK_AND_RETURN_RET_LOG(MediaFileUtils::CreateFile(path), E_HAS_FS_ERROR,
                "Create file failed, path:%{private}s", path.c_str());
        } else {
            MEDIA_WARN_LOG("Unexpected source file already exists for a not-edited asset, display name: %{private}s",
                fileAsset->GetDisplayName().c_str());
        }
    }

    return OpenFileWithPrivacy(path, "rw");
}

static int32_t UpdateEditTime(int32_t fileId, int64_t time)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        return E_HAS_DB_ERROR;
    }
    MediaLibraryCommand updatePendingCmd(OperationObject::FILESYSTEM_PHOTO, OperationType::UPDATE);
    updatePendingCmd.GetAbsRdbPredicates()->EqualTo(MediaColumn::MEDIA_ID, to_string(fileId));
    ValuesBucket updateValues;
    updateValues.PutLong(PhotoColumn::PHOTO_EDIT_TIME, time);
    updatePendingCmd.SetValueBucket(updateValues);
    int32_t rowId = 0;
    int32_t result = rdbStore->Update(updatePendingCmd, rowId);
    if (result != NativeRdb::E_OK || rowId <= 0) {
        MEDIA_ERR_LOG("Update File pending failed. Result %{public}d.", result);
        return E_HAS_DB_ERROR;
    }

    return E_OK;
}

int32_t MediaLibraryPhotoOperations::CommitEditInsert(MediaLibraryCommand &cmd)
{
    const ValuesBucket &values = cmd.GetValueBucket();
    string editData;
    int32_t id = 0;
    if (!GetInt32FromValuesBucket(values, PhotoColumn::MEDIA_ID, id)) {
        MEDIA_ERR_LOG("Failed to get fileId");
        PhotoEditingRecord::GetInstance()->EndCommitEdit(id);
        return E_INVALID_VALUES;
    }
    if (!GetStringFromValuesBucket(values, EDIT_DATA, editData)) {
        MEDIA_ERR_LOG("Failed to get editdata");
        PhotoEditingRecord::GetInstance()->EndCommitEdit(id);
        return E_INVALID_VALUES;
    }

    shared_ptr<FileAsset> fileAsset = GetFileAssetFromDb(PhotoColumn::MEDIA_ID, to_string(id),
        OperationObject::FILESYSTEM_PHOTO, EDITED_COLUMN_VECTOR);
    if (fileAsset == nullptr) {
        MEDIA_ERR_LOG("Get FileAsset Failed, fileId=%{public}d", id);
        PhotoEditingRecord::GetInstance()->EndCommitEdit(id);
        return E_INVALID_VALUES;
    }
    fileAsset->SetId(id);
    int32_t ret = CommitEditInsertExecute(fileAsset, editData);
    PhotoEditingRecord::GetInstance()->EndCommitEdit(id);
    MEDIA_INFO_LOG("commit edit finished, fileId=%{public}d", id);
    return ret;
}

static void NotifyFormMap(const int32_t fileId, const string& path, const bool isSave)
{
    string uri = MediaLibraryFormMapOperations::GetUriByFileId(fileId, path);
    if (uri.empty()) {
        MEDIA_WARN_LOG("Failed to GetUriByFileId(%{public}d, %{private}s)", fileId, path.c_str());
        return;
    }

    vector<int64_t> formIds;
    MediaLibraryFormMapOperations::GetFormMapFormId(uri.c_str(), formIds);
    if (!formIds.empty()) {
        MediaLibraryFormMapOperations::PublishedChange(uri, formIds, isSave);
    }
}

int32_t MediaLibraryPhotoOperations::CommitEditInsertExecute(const shared_ptr<FileAsset> &fileAsset,
    const string &editData)
{
    if (fileAsset == nullptr) {
        return E_INVALID_VALUES;
    }

    if (fileAsset->GetTimePending() != 0) {
        MEDIA_ERR_LOG("FileAsset is in PendingStatus %{public}ld", static_cast<long>(fileAsset->GetTimePending()));
        return E_IS_PENDING_ERROR;
    }
    if (fileAsset->GetDateTrashed() != 0) {
        MEDIA_ERR_LOG("FileAsset is in recycle");
        return E_IS_RECYCLED;
    }

    string path = fileAsset->GetPath();
    CHECK_AND_RETURN_RET_LOG(!path.empty(), E_INVALID_VALUES, "File path is empty");
    string editDataPath = GetEditDataPath(path);
    CHECK_AND_RETURN_RET_LOG(!editDataPath.empty(), E_INVALID_VALUES, "EditData path is empty");
    if (!MediaFileUtils::IsFileExists(editDataPath)) {
        string dataPathDir = GetEditDataDirPath(path);
        CHECK_AND_RETURN_RET_LOG(!dataPathDir.empty(), E_INVALID_PATH,
            "Get edit data dir path from path %{private}s failed", path.c_str());
        if (!MediaFileUtils::IsDirectory(dataPathDir)) {
            CHECK_AND_RETURN_RET_LOG(MediaFileUtils::CreateDirectory(dataPathDir), E_HAS_FS_ERROR,
                "Failed to create dir %{private}s", dataPathDir.c_str());
        }
        CHECK_AND_RETURN_RET_LOG(MediaFileUtils::CreateAsset(editDataPath) == E_SUCCESS, E_HAS_FS_ERROR,
            "Failed to create file %{private}s", editDataPath.c_str());
    }
    CHECK_AND_RETURN_RET_LOG(MediaFileUtils::WriteStrToFile(editDataPath, editData), E_HAS_FS_ERROR,
        "Failed to write editdata path:%{private}s", editDataPath.c_str());

    MediaLibraryRdbUtils::UpdateSystemAlbumInternal(
        MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw(), {
        to_string(PhotoAlbumSubType::IMAGE),
        to_string(PhotoAlbumSubType::VIDEO),
        to_string(PhotoAlbumSubType::SCREENSHOT),
        to_string(PhotoAlbumSubType::FAVORITE),
    });
    int32_t errCode = UpdateEditTime(fileAsset->GetId(), MediaFileUtils::UTCTimeSeconds());
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "Failed to update edit time, fileId:%{public}d",
        fileAsset->GetId());
    ScanFile(path, true, true, true);
    NotifyFormMap(fileAsset->GetId(), fileAsset->GetFilePath(), false);
    return E_OK;
}

int32_t MediaLibraryPhotoOperations::RevertToOrigin(MediaLibraryCommand &cmd)
{
    const ValuesBucket &values = cmd.GetValueBucket();
    int32_t fileId = 0;
    CHECK_AND_RETURN_RET_LOG(GetInt32FromValuesBucket(values, PhotoColumn::MEDIA_ID, fileId), E_INVALID_VALUES,
        "Failed to get fileId");

    shared_ptr<FileAsset> fileAsset = GetFileAssetFromDb(PhotoColumn::MEDIA_ID, to_string(fileId),
        OperationObject::FILESYSTEM_PHOTO, EDITED_COLUMN_VECTOR);
    if (fileAsset == nullptr) {
        MEDIA_ERR_LOG("Get FileAsset From Uri Failed, fileId:%{public}d", fileId);
        return E_INVALID_VALUES;
    }
    fileAsset->SetId(fileId);
    if (!PhotoEditingRecord::GetInstance()->StartRevert(fileId)) {
        return E_IS_IN_COMMIT;
    }

    int32_t errCode = DoRevertEdit(fileAsset);
    PhotoEditingRecord::GetInstance()->EndRevert(fileId);
    return errCode;
}

int32_t MediaLibraryPhotoOperations::DoRevertEdit(const std::shared_ptr<FileAsset> &fileAsset)
{
    if (fileAsset == nullptr) {
        return E_INVALID_VALUES;
    }

    int32_t fileId = fileAsset->GetId();
    if (fileAsset->GetTimePending() != 0) {
        MEDIA_ERR_LOG("FileAsset is in PendingStatus %{public}ld", static_cast<long>(fileAsset->GetTimePending()));
        return E_IS_PENDING_ERROR;
    }
    if (fileAsset->GetDateTrashed() != 0) {
        MEDIA_ERR_LOG("FileAsset is in recycle");
        return E_IS_RECYCLED;
    }
    if (fileAsset->GetPhotoEditTime() == 0) {
        MEDIA_INFO_LOG("File %{public}d is not edit", fileId);
        return E_OK;
    }

    string path = fileAsset->GetFilePath();
    CHECK_AND_RETURN_RET_LOG(!path.empty(), E_INVALID_URI, "Can not get file path, fileId=%{public}d", fileId);
    string sourcePath = GetEditDataSourcePath(path);
    CHECK_AND_RETURN_RET_LOG(!sourcePath.empty(), E_INVALID_URI, "Cannot get source path, id=%{public}d", fileId);
    CHECK_AND_RETURN_RET_LOG(MediaFileUtils::IsFileExists(sourcePath), E_NO_SUCH_FILE, "Can not get source file");

    string editDataPath = GetEditDataPath(path);
    CHECK_AND_RETURN_RET_LOG(!editDataPath.empty(), E_INVALID_URI, "Cannot get editdata path, id=%{public}d", fileId);
    if (MediaFileUtils::IsFileExists(editDataPath)) {
        CHECK_AND_RETURN_RET_LOG(MediaFileUtils::DeleteFile(editDataPath), E_HAS_FS_ERROR,
            "Failed to delete edit data, path:%{private}s", editDataPath.c_str());
    }

    if (MediaFileUtils::IsFileExists(path)) {
        CHECK_AND_RETURN_RET_LOG(MediaFileUtils::DeleteFile(path), E_HAS_FS_ERROR,
            "Failed to delete asset, path:%{private}s", path.c_str());
    }
    CHECK_AND_RETURN_RET_LOG(MediaFileUtils::ModifyAsset(sourcePath, path) == E_OK, E_HAS_FS_ERROR,
        "Can not modify %{private}s to %{private}s", sourcePath.c_str(), path.c_str());

    int32_t errCode = UpdateEditTime(fileId, 0);
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, E_HAS_DB_ERROR, "Failed to update edit time, fileId=%{public}d",
        fileId);
    ScanFile(path, true, true, true);
    NotifyFormMap(fileAsset->GetId(), fileAsset->GetFilePath(), false);
    return E_OK;
}

void MediaLibraryPhotoOperations::DeleteRevertMessage(const string &path)
{
    if (path.empty()) {
        MEDIA_ERR_LOG("Input path is empty");
        return;
    }

    string editDirPath = GetEditDataDirPath(path);
    if (editDirPath.empty()) {
        MEDIA_ERR_LOG("Can not get edit data dir path from path %{private}s", path.c_str());
        return;
    }

    if (!MediaFileUtils::IsDirectory(editDirPath)) {
        return;
    }
    if (!MediaFileUtils::DeleteDir(editDirPath)) {
        MEDIA_ERR_LOG("Failed to delete %{private}s dir, filePath is %{private}s",
            editDirPath.c_str(), path.c_str());
        return;
    }
    return;
}

static int32_t MoveCache(const string& srcPath, const string& destPath)
{
    if (!MediaFileUtils::IsFileExists(srcPath)) {
        MEDIA_ERR_LOG("srcPath: %{private}s does not exist!", srcPath.c_str());
        return E_NO_SUCH_FILE;
    }

    if (destPath.empty()) {
        MEDIA_ERR_LOG("Failed to check empty destPath");
        return E_INVALID_VALUES;
    }

    std::error_code errCode;
    filesystem::path dest(destPath);
    if (filesystem::exists(dest) && !filesystem::remove(dest, errCode)) {
        MEDIA_ERR_LOG("Failed to remove %{private}s, errCode: %{public}d", destPath.c_str(), errCode.value());
        return errCode.value();
    }

    filesystem::path src(srcPath);
    filesystem::rename(src, dest, errCode);
    return errCode.value();
}

int32_t MediaLibraryPhotoOperations::MoveCacheFile(
    MediaLibraryCommand& cmd, int32_t subtype, const string& cachePath, const string& destPath)
{
    if (subtype != static_cast<int32_t>(PhotoSubType::MOVING_PHOTO)) {
        return MoveCache(cachePath, destPath);
    }

    // write moving photo
    CHECK_AND_RETURN_RET_LOG(MediaFileUtils::CheckMovingPhotoImage(cachePath), E_INVALID_MOVING_PHOTO,
        "Failed to check image of moving photo");
    string cacheMovingPhotoVideoName;
    if (GetStringFromValuesBucket(cmd.GetValueBucket(), CACHE_MOVING_PHOTO_VIDEO_NAME, cacheMovingPhotoVideoName)) {
        string cacheVideoPath = GetAssetCacheDir() + "/" + cacheMovingPhotoVideoName;
        CHECK_AND_RETURN_RET_LOG(MediaFileUtils::CheckMovingPhotoVideo(cacheVideoPath), E_INVALID_MOVING_PHOTO,
            "Failed to check video of moving photo");
        string destVideoPath = MediaFileUtils::GetMovingPhotoVideoPath(destPath);
        int32_t errCode = MoveCache(cacheVideoPath, destVideoPath);
        CHECK_AND_RETURN_RET_LOG(errCode == E_OK, E_FILE_OPER_FAIL,
            "Failed to move moving photo video from %{private}s to %{private}s, errCode: %{public}d",
            cacheVideoPath.c_str(), destVideoPath.c_str(), errCode);
    }
    return MoveCache(cachePath, destPath);
}

bool MediaLibraryPhotoOperations::CheckCacheCmd(MediaLibraryCommand& cmd, int32_t subtype, const string& displayName)
{
    string cacheFileName;
    if (!GetStringFromValuesBucket(cmd.GetValueBucket(), CACHE_FILE_NAME, cacheFileName)) {
        MEDIA_ERR_LOG("Failed to get cache file name");
        return false;
    }
    string cacheMimeType = MimeTypeUtils::GetMimeTypeFromExtension(MediaFileUtils::GetExtensionFromPath(cacheFileName));
    string assetMimeType = MimeTypeUtils::GetMimeTypeFromExtension(MediaFileUtils::GetExtensionFromPath(displayName));

    if (cacheMimeType.compare(assetMimeType) != 0) {
        MEDIA_ERR_LOG("cache mime type %{public}s mismatches the asset %{public}s",
            cacheMimeType.c_str(), assetMimeType.c_str());
        return false;
    }

    int32_t id = 0;
    bool isCreation = !GetInt32FromValuesBucket(cmd.GetValueBucket(), PhotoColumn::MEDIA_ID, id);
    if (subtype == static_cast<int32_t>(PhotoSubType::MOVING_PHOTO) && isCreation) {
        string movingPhotoVideoName;
        bool containsVideo = GetStringFromValuesBucket(cmd.GetValueBucket(),
            CACHE_MOVING_PHOTO_VIDEO_NAME, movingPhotoVideoName);
        if (!containsVideo) {
            MEDIA_ERR_LOG("Failed to get video when creating moving photo");
            return false;
        }

        string videoExtension = MediaFileUtils::GetExtensionFromPath(movingPhotoVideoName);
        if (!MediaFileUtils::CheckMovingPhotoVideoExtension(videoExtension)) {
            MEDIA_ERR_LOG("Failed to check video of moving photo, extension: %{public}s", videoExtension.c_str());
            return false;
        }
    }
    return true;
}

int32_t MediaLibraryPhotoOperations::ParseMediaAssetEditData(MediaLibraryCommand& cmd, string& editData)
{
    string compatibleFormat;
    string formatVersion;
    string data;
    const ValuesBucket& values = cmd.GetValueBucket();
    bool containsCompatibleFormat = GetStringFromValuesBucket(values, COMPATIBLE_FORMAT, compatibleFormat);
    bool containsFormatVersion = GetStringFromValuesBucket(values, FORMAT_VERSION, formatVersion);
    bool containsData = GetStringFromValuesBucket(values, EDIT_DATA, data);
    bool notContainsEditData = !containsCompatibleFormat && !containsFormatVersion && !containsData;
    bool containsEditData = containsCompatibleFormat && containsFormatVersion && containsData;
    if (!containsEditData && !notContainsEditData) {
        MEDIA_ERR_LOG(
            "Failed to parse edit data, compatibleFormat: %{public}s, formatVersion: %{public}s, data: %{public}s",
            compatibleFormat.c_str(), formatVersion.c_str(), data.c_str());
        return E_INVALID_VALUES;
    }

    nlohmann::json editDataJson;
    string bundleName = cmd.GetBundleName();
    editDataJson[COMPATIBLE_FORMAT] = compatibleFormat.empty() ? bundleName : compatibleFormat;
    editDataJson[FORMAT_VERSION] = formatVersion;
    editDataJson[EDIT_DATA] = data;
    editDataJson[APP_ID] = bundleName;
    editData = editDataJson.dump();
    return E_OK;
}

int32_t MediaLibraryPhotoOperations::SaveSourceAndEditData(
    const shared_ptr<FileAsset>& fileAsset, const string& editData)
{
    CHECK_AND_RETURN_RET_LOG(fileAsset != nullptr, E_INVALID_VALUES, "fileAsset is nullptr");
    string assetPath = fileAsset->GetFilePath();
    CHECK_AND_RETURN_RET_LOG(!assetPath.empty(), E_INVALID_VALUES, "Failed to get asset path");
    string editDataPath = GetEditDataPath(assetPath);
    CHECK_AND_RETURN_RET_LOG(!editDataPath.empty(), E_INVALID_VALUES, "Failed to get edit data path");

    if (fileAsset->GetPhotoEditTime() == 0) { // the asset has not been edited before
        string editDataDirPath = GetEditDataDirPath(assetPath);
        CHECK_AND_RETURN_RET_LOG(!editDataDirPath.empty(), E_INVALID_URI, "Failed to get edit dir path");
        CHECK_AND_RETURN_RET_LOG(MediaFileUtils::CreateDirectory(editDataDirPath), E_HAS_FS_ERROR,
            "Failed to create dir %{private}s", editDataDirPath.c_str());

        string sourcePath = GetEditDataSourcePath(assetPath);
        CHECK_AND_RETURN_RET_LOG(!sourcePath.empty(), E_INVALID_URI, "Failed to get source path");
        if (!MediaFileUtils::IsFileExists(sourcePath)) {
            CHECK_AND_RETURN_RET_LOG(MediaFileUtils::ModifyAsset(assetPath, sourcePath) == E_SUCCESS, E_HAS_FS_ERROR,
                "Move file failed, srcPath:%{private}s, newPath:%{private}s", assetPath.c_str(), sourcePath.c_str());
        }

        if (!MediaFileUtils::IsFileExists(editDataPath)) {
            CHECK_AND_RETURN_RET_LOG(MediaFileUtils::CreateFile(editDataPath), E_HAS_FS_ERROR,
                "Failed to create file %{private}s", editDataPath.c_str());
        }
    }

    CHECK_AND_RETURN_RET_LOG(MediaFileUtils::WriteStrToFile(editDataPath, editData), E_HAS_FS_ERROR,
        "Failed to write editdata:%{private}s", editDataPath.c_str());
    return E_OK;
}

int32_t MediaLibraryPhotoOperations::SubmitEditCacheExecute(MediaLibraryCommand& cmd,
    const shared_ptr<FileAsset>& fileAsset, const string& cachePath)
{
    int32_t subtype = fileAsset->GetPhotoSubType();
    if (subtype == static_cast<int32_t>(PhotoSubType::MOVING_PHOTO)) {
        MEDIA_ERR_LOG("Moving photo is not supported to edit now");
        return E_INVALID_VALUES;
    }

    string editData;
    int32_t id = fileAsset->GetId();
    int32_t errCode = ParseMediaAssetEditData(cmd, editData);
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "Failed to parse MediaAssetEditData");
    errCode = SaveSourceAndEditData(fileAsset, editData);
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "Failed to save source and editData");

    string assetPath = fileAsset->GetFilePath();
    errCode = MoveCacheFile(cmd, subtype, cachePath, assetPath);
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, E_FILE_OPER_FAIL,
        "Failed to move %{private}s to %{private}s, errCode: %{public}d",
        cachePath.c_str(), assetPath.c_str(), errCode);

    errCode = UpdateEditTime(id, MediaFileUtils::UTCTimeSeconds());
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "Failed to update edit time, fileId:%{public}d", id);
    ScanFile(assetPath, true, true, true);
    NotifyFormMap(id, assetPath, false);
    MediaLibraryVisionOperations::EditCommitOperation(cmd);
    return E_OK;
}

int32_t MediaLibraryPhotoOperations::SubmitCacheExecute(MediaLibraryCommand& cmd,
    const shared_ptr<FileAsset>& fileAsset, const string& cachePath)
{
    CHECK_AND_RETURN_RET_LOG(fileAsset != nullptr, E_INVALID_VALUES, "fileAsset is nullptr");
    int32_t subtype = fileAsset->GetPhotoSubType();
    CHECK_AND_RETURN_RET_LOG(CheckCacheCmd(cmd, subtype, fileAsset->GetDisplayName()),
        E_INVALID_VALUES, "Failed to check cache cmd");
    CHECK_AND_RETURN_RET_LOG(fileAsset->GetDateTrashed() == 0, E_IS_RECYCLED, "FileAsset is in recycle");

    int64_t pending = fileAsset->GetTimePending();
    CHECK_AND_RETURN_RET_LOG(
        pending == 0 || pending == UNCREATE_FILE_TIMEPENDING || pending == UNOPEN_FILE_COMPONENT_TIMEPENDING,
        E_IS_PENDING_ERROR, "FileAsset is in pending: %{public}ld", static_cast<long>(pending));

    string assetPath = fileAsset->GetFilePath();
    CHECK_AND_RETURN_RET_LOG(!assetPath.empty(), E_INVALID_VALUES, "Failed to get asset path");

    int32_t id = fileAsset->GetId();
    bool isEdit = (pending == 0);
    if (isEdit) {
        if (!PhotoEditingRecord::GetInstance()->StartCommitEdit(id)) {
            return E_IS_IN_REVERT;
        }
        int32_t errCode = SubmitEditCacheExecute(cmd, fileAsset, cachePath);
        PhotoEditingRecord::GetInstance()->EndCommitEdit(id);
        return errCode;
    }

    int32_t errCode = MoveCacheFile(cmd, subtype, cachePath, assetPath);
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, E_FILE_OPER_FAIL,
        "Failed to move %{private}s to %{private}s, errCode: %{public}d",
        cachePath.c_str(), assetPath.c_str(), errCode);
    ScanFile(assetPath, true, true, true);
    return E_OK;
}

int32_t MediaLibraryPhotoOperations::SubmitCache(MediaLibraryCommand& cmd)
{
    const ValuesBucket& values = cmd.GetValueBucket();
    string fileName;
    CHECK_AND_RETURN_RET_LOG(GetStringFromValuesBucket(values, CACHE_FILE_NAME, fileName),
        E_INVALID_VALUES, "Failed to get fileName");
    string cacheDir = GetAssetCacheDir();
    string cachePath = cacheDir + "/" + fileName;
    CHECK_AND_RETURN_RET_LOG(MediaFileUtils::IsFileExists(cachePath), E_NO_SUCH_FILE,
        "cachePath: %{private}s does not exist!", cachePath.c_str());
    string movingPhotoVideoName;
    if (GetStringFromValuesBucket(values, CACHE_MOVING_PHOTO_VIDEO_NAME, movingPhotoVideoName)) {
        CHECK_AND_RETURN_RET_LOG(MediaFileUtils::IsFileExists(cacheDir + "/" + movingPhotoVideoName),
            E_NO_SUCH_FILE, "cahce moving video path: %{private}s does not exist!", cachePath.c_str());
    }

    int32_t id = 0;
    if (!GetInt32FromValuesBucket(values, PhotoColumn::MEDIA_ID, id)) {
        string displayName;
        CHECK_AND_RETURN_RET_LOG(GetStringFromValuesBucket(values, PhotoColumn::MEDIA_NAME, displayName),
            E_INVALID_VALUES, "Failed to get displayName");
        CHECK_AND_RETURN_RET_LOG(
            MediaFileUtils::GetExtensionFromPath(displayName) == MediaFileUtils::GetExtensionFromPath(fileName),
            E_INVALID_VALUES, "displayName mismatches extension of cache file name");
        ValuesBucket reservedValues = values;
        id = CreateV10(cmd);
        CHECK_AND_RETURN_RET_LOG(id > 0, E_FAIL, "Failed to create asset");
        cmd.SetValueBucket(reservedValues);
    }

    vector<string> columns = { PhotoColumn::MEDIA_ID, PhotoColumn::MEDIA_FILE_PATH, PhotoColumn::MEDIA_NAME,
        PhotoColumn::PHOTO_SUBTYPE, PhotoColumn::MEDIA_TIME_PENDING, PhotoColumn::MEDIA_DATE_TRASHED };
    shared_ptr<FileAsset> fileAsset = GetFileAssetFromDb(
        PhotoColumn::MEDIA_ID, to_string(id), OperationObject::FILESYSTEM_PHOTO, columns);
    CHECK_AND_RETURN_RET_LOG(fileAsset != nullptr, E_INVALID_VALUES, "Failed to get FileAsset, fileId=%{public}d", id);
    int32_t errCode = SubmitCacheExecute(cmd, fileAsset, cachePath);
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "Failed to submit cache, fileId=%{public}d", id);
    return id;
}

PhotoEditingRecord::PhotoEditingRecord()
{
}

shared_ptr<PhotoEditingRecord> PhotoEditingRecord::GetInstance()
{
    if (instance_ == nullptr) {
        lock_guard<mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = make_shared<PhotoEditingRecord>();
        }
    }
    return instance_;
}

bool PhotoEditingRecord::StartCommitEdit(int32_t fileId)
{
    unique_lock<shared_mutex> lock(addMutex_);
    if (revertingPhotoSet_.count(fileId) > 0) {
        MEDIA_ERR_LOG("Photo %{public}d is reverting", fileId);
        return false;
    }
    editingPhotoSet_.insert(fileId);
    return true;
}

void PhotoEditingRecord::EndCommitEdit(int32_t fileId)
{
    unique_lock<shared_mutex> lock(addMutex_);
    editingPhotoSet_.erase(fileId);
}

bool PhotoEditingRecord::StartRevert(int32_t fileId)
{
    unique_lock<shared_mutex> lock(addMutex_);
    if (editingPhotoSet_.count(fileId) > 0) {
        MEDIA_ERR_LOG("Photo %{public}d is committing edit", fileId);
        return false;
    }
    revertingPhotoSet_.insert(fileId);
    return true;
}

void PhotoEditingRecord::EndRevert(int32_t fileId)
{
    unique_lock<shared_mutex> lock(addMutex_);
    revertingPhotoSet_.erase(fileId);
}

bool PhotoEditingRecord::IsInRevertOperation(int32_t fileId)
{
    shared_lock<shared_mutex> lock(addMutex_);
    return revertingPhotoSet_.count(fileId) > 0;
}

bool PhotoEditingRecord::IsInEditOperation(int32_t fileId)
{
    shared_lock<shared_mutex> lock(addMutex_);
    if (editingPhotoSet_.count(fileId) > 0 || revertingPhotoSet_.count(fileId) > 0) {
        return true;
    }
    return false;
}

void MediaLibraryPhotoOperations::StoreThumbnailSize(const string& photoId, const string& photoPath)
{
    auto mediaLibraryRdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (mediaLibraryRdbStore == nullptr) {
        MEDIA_ERR_LOG("Medialibrary rdbStore is nullptr!");
        return;
    }
    auto rdbStore = mediaLibraryRdbStore->GetRaw();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("RdbStore is nullptr!");
        return;
    }

    size_t LCDThumbnailSize = 0;
    size_t THMThumbnailSize = 0;
    size_t THMASTCThumbnailSize = 0;
    if (!MediaFileUtils::GetFileSize(GetThumbnailPath(photoPath, THUMBNAIL_LCD_SUFFIX), LCDThumbnailSize)) {
        MEDIA_WARN_LOG("Failed to get LCD thumbnail size for photo id %{public}s", photoId.c_str());
    }
    if (!MediaFileUtils::GetFileSize(GetThumbnailPath(photoPath, THUMBNAIL_THUMB_SUFFIX), THMThumbnailSize)) {
        MEDIA_WARN_LOG("Failed to get THM thumbnail size for photo id %{public}s", photoId.c_str());
    }
    if (!MediaFileUtils::GetFileSize(GetThumbnailPath(photoPath, THUMBNAIL_THUMBASTC_SUFFIX), THMASTCThumbnailSize)) {
        MEDIA_WARN_LOG("Failed to get THM_ASTC thumbnail size for photo id %{public}s", photoId.c_str());
    }
    size_t photoThumbnailSize = LCDThumbnailSize + THMThumbnailSize + THMASTCThumbnailSize;

    string sql = "INSERT OR REPLACE INTO " + PhotoExtColumn::PHOTOS_EXT_TABLE + " (" +
        PhotoExtColumn::PHOTO_ID + ", " + PhotoExtColumn::THUMBNAIL_SIZE +
        ") VALUES (" + photoId + ", " + to_string(photoThumbnailSize) + ")";

    int32_t ret = rdbStore->ExecuteSql(sql);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Failed to execute sql, photoId is %{public}s, error code is %{public}d", photoId.c_str(), ret);
    }
}

void MediaLibraryPhotoOperations::RemoveThumbnailSizeRecord(const string& photoId)
{
    auto mediaLibraryRdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (mediaLibraryRdbStore == nullptr) {
        MEDIA_ERR_LOG("Medialibrary rdbStore is nullptr!");
        return;
    }
    auto rdbStore = mediaLibraryRdbStore->GetRaw();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("RdbStore is nullptr!");
        return;
    }

    string sql = "DELETE FROM " + PhotoExtColumn::PHOTOS_EXT_TABLE +
        " WHERE " + PhotoExtColumn::PHOTO_ID + " = " + photoId + ";";
    int32_t ret = rdbStore->ExecuteSql(sql);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Failed to execute sql, photoId is %{public}s, error code is %{public}d", photoId.c_str(), ret);
    }
}

} // namespace Media
} // namespace OHOS

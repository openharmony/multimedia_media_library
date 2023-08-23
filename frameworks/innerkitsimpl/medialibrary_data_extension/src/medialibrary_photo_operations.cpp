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

#include <memory>

#include "abs_shared_result_set.h"
#include "file_asset.h"
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
#include "medialibrary_notify.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_rdb_transaction.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_tracer.h"
#include "medialibrary_type_const.h"
#include "medialibrary_uripermission_operations.h"
#include "photo_album_column.h"
#include "photo_map_column.h"
#include "photo_map_operations.h"
#include "rdb_predicates.h"
#include "result_set_utils.h"
#include "thumbnail_const.h"
#include "userfile_manager_types.h"
#include "value_object.h"
#include "values_bucket.h"

using namespace OHOS::DataShare;
using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::RdbDataShareAdapter;

namespace OHOS {
namespace Media {

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

int32_t MediaLibraryPhotoOperations::Delete(MediaLibraryCommand& cmd)
{
    string fileId = cmd.GetOprnFileId();
    vector<string> columns = {
        PhotoColumn::MEDIA_ID,
        PhotoColumn::MEDIA_FILE_PATH,
        PhotoColumn::MEDIA_RELATIVE_PATH,
        PhotoColumn::MEDIA_TYPE
    };
    shared_ptr<FileAsset> fileAsset = GetFileAssetFromDb(*(cmd.GetAbsRdbPredicates()),
        cmd.GetOprnObject(), columns);
    CHECK_AND_RETURN_RET_LOG(fileAsset != nullptr, E_INVALID_FILEID, "Get fileAsset failed, fileId: %{public}s",
        fileId.c_str());
    int32_t deleteRow = DeletePhoto(fileAsset, cmd.GetApi());
    CHECK_AND_RETURN_RET_LOG(deleteRow >= 0, deleteRow, "delete photo failed, deleteRow=%{public}d", deleteRow);

    return deleteRow;
}

static void HandleGroupBy(AbsPredicates &predicates, const vector<string> &columns)
{
    auto it = find(columns.begin(), columns.end(), MEDIA_COLUMN_COUNT);
    if (it == columns.end()) {
        return;
    }
    if (!predicates.GetGroup().empty()) {
        return;
    }
    string whereClause = predicates.GetWhereClause();
    predicates.SetWhereClause(whereClause +
        " GROUP BY (DATE(date_added, 'unixepoch', 'localtime')) ORDER BY date_added DESC ");
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
        PhotoAlbumColumns::GetUserAlbumPredicates(stoi(albumId), predicates);
        return E_SUCCESS;
    }

    if ((type != PhotoAlbumType::SYSTEM) || (subType == PhotoAlbumSubType::USER_GENERIC) ||
        (subType == PhotoAlbumSubType::ANY)) {
        MEDIA_ERR_LOG("album id %{private}s type:%d subtype:%d", albumId.c_str(), type, subType);
        return E_INVALID_ARGUMENTS;
    }
    PhotoAlbumColumns::GetSystemAlbumPredicates(subType, predicates);
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
        return MediaLibraryRdbStore::GetIndexOfUri(predicates, columns, photoId);
    }
}

shared_ptr<NativeRdb::ResultSet> MediaLibraryPhotoOperations::Query(
    MediaLibraryCommand &cmd, const vector<string> &columns)
{
    RdbPredicates predicates = RdbUtils::ToPredicates(cmd.GetDataSharePred(), PhotoColumn::PHOTOS_TABLE);
    if (cmd.GetOprnType() == OperationType::INDEX) {
        constexpr int32_t COLUMN_SIZE = 2;
        CHECK_AND_RETURN_RET_LOG(columns.size() >= COLUMN_SIZE, nullptr, "invalid id param");
        constexpr int32_t PHOTO_ID_INDEX = 0;
        constexpr int32_t ALBUM_ID_INDEX = 1;
        string photoId = columns[PHOTO_ID_INDEX];
        string albumId;
        if (!columns[ALBUM_ID_INDEX].empty()) {
            albumId = columns[ALBUM_ID_INDEX];
        }
        return HandleIndexOfUri(cmd, predicates, photoId, albumId);
    } else {
        HandleGroupBy(predicates, columns);
        return MediaLibraryRdbStore::Query(predicates, columns);
    }
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

// temp function, delete after MediaFileUri::Getpath is finish
static string GetPathFromUri(const std::string &uri)
{
    string realTitle = uri;
    size_t index = uri.rfind('/');
    if (index == string::npos) {
        return "";
    }
    realTitle = uri.substr(0, index);
    index = realTitle.rfind('/');
    if (index == string::npos) {
        return "";
    }
    realTitle = realTitle.substr(index + 1);
    index = realTitle.rfind('_');
    if (index == string::npos) {
        return "";
    }
    int32_t fileUniqueId = stoi(realTitle.substr(index + 1));
    int32_t bucketNum = 0;
    MediaLibraryAssetOperations::CreateAssetBucket(fileUniqueId, bucketNum);
    string ext = MediaFileUtils::GetExtensionFromPath(uri);
    if (ext.empty()) {
        return "";
    }

    string path = ROOT_MEDIA_DIR + PHOTO_BUCKET + "/" + to_string(bucketNum) + "/" + realTitle + "." + ext;
    if (!MediaFileUtils::IsFileExists(path)) {
        MEDIA_ERR_LOG("file not exist, path=%{private}s", path.c_str());
        return "";
    }
    return path;
}

const static vector<string> PHOTO_COLUMN_VECTOR = {
    PhotoColumn::MEDIA_FILE_PATH,
    PhotoColumn::MEDIA_TYPE,
    PhotoColumn::MEDIA_TIME_PENDING
};

int32_t MediaLibraryPhotoOperations::Open(MediaLibraryCommand &cmd, const string &mode)
{
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryPhotoOperations::Open");

    string uriString = cmd.GetUriStringWithoutSegment();
    string id = MediaLibraryDataManagerUtils::GetIdFromUri(uriString);
    if (uriString.empty() || (!MediaLibraryDataManagerUtils::IsNumber(id))) {
        return E_INVALID_URI;
    }

    shared_ptr<FileAsset> fileAsset = make_shared<FileAsset>();
    string pendingStatus = cmd.GetQuerySetParam(MediaColumn::MEDIA_TIME_PENDING);
    MediaFileUri fileUri(uriString);
    if (pendingStatus.empty() || !fileUri.IsApi10()) {
        fileAsset = GetFileAssetFromDb(PhotoColumn::MEDIA_ID, id, OperationObject::FILESYSTEM_PHOTO,
            PHOTO_COLUMN_VECTOR);
        if (fileAsset == nullptr) {
            MEDIA_ERR_LOG("Failed to obtain path from Database, uri=%{private}s", uriString.c_str());
            return E_INVALID_URI;
        }
    } else {
        string path = GetPathFromUri(uriString);
        if (path.empty()) {
            fileAsset = GetFileAssetFromDb(PhotoColumn::MEDIA_ID, id, OperationObject::FILESYSTEM_PHOTO,
                PHOTO_COLUMN_VECTOR);
            if (fileAsset == nullptr) {
                MEDIA_ERR_LOG("Failed to obtain path from Database, uri=%{private}s", uriString.c_str());
                return E_INVALID_URI;
            }
        } else {
            fileAsset->SetPath(path);
            fileAsset->SetMediaType(MediaFileUtils::GetMediaType(path));
            int32_t timePending = stoi(pendingStatus);
            fileAsset->SetTimePending((timePending > 0) ? MediaFileUtils::UTCTimeSeconds() : timePending);
        }
    }

    fileAsset->SetId(stoi(id));
    fileAsset->SetUri(uriString);

    if (uriString.find(PhotoColumn::PHOTO_URI_PREFIX) != string::npos) {
        return OpenAsset(fileAsset, mode, MediaLibraryApi::API_10);
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
    string fileId = MediaLibraryDataManagerUtils::GetIdFromUri(uriString);
    if (uriString.empty() || (!MediaLibraryDataManagerUtils::IsNumber(fileId))) {
        return E_INVALID_URI;
    }

    shared_ptr<FileAsset> fileAsset = make_shared<FileAsset>();
    string pendingStatus = cmd.GetQuerySetParam(MediaColumn::MEDIA_TIME_PENDING);
    MediaFileUri fileUri(uriString);
    if (pendingStatus.empty() || !fileUri.IsApi10()) {
        fileAsset = GetFileAssetFromDb(PhotoColumn::MEDIA_ID, fileId, OperationObject::FILESYSTEM_PHOTO,
            PHOTO_COLUMN_VECTOR);
        if (fileAsset == nullptr) {
            MEDIA_ERR_LOG("Failed to obtain path from Database, uri=%{private}s", uriString.c_str());
            return E_INVALID_URI;
        }
    } else {
        string path = GetPathFromUri(uriString);
        if (path.empty()) {
            fileAsset = GetFileAssetFromDb(PhotoColumn::MEDIA_ID, fileId, OperationObject::FILESYSTEM_PHOTO,
                PHOTO_COLUMN_VECTOR);
            if (fileAsset == nullptr) {
                MEDIA_ERR_LOG("Failed to obtain path from Database, uri=%{private}s", uriString.c_str());
                return E_INVALID_URI;
            }
        } else {
            fileAsset->SetPath(path);
            fileAsset->SetMediaType(MediaFileUtils::GetMediaType(path));
            int32_t timePending = stoi(pendingStatus);
            fileAsset->SetTimePending((timePending > 0) ? MediaFileUtils::UTCTimeSeconds() : timePending);
        }
    }

    fileAsset->SetId(stoi(fileId));
    fileAsset->SetUri(uriString);

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
            NotifyType::NOTIFY_ALBUM_ADD_ASSERT, albumId);
    }
}

void MediaLibraryPhotoOperations::SolvePhotoAlbumInCreate(MediaLibraryCommand &cmd, FileAsset &fileAsset)
{
    ValuesBucket &values = cmd.GetValueBucket();
    string albumUri;
    GetStringFromValuesBucket(values, MEDIA_DATA_DB_ALARM_URI, albumUri);
    if (!albumUri.empty()) {
        PhotoMapAddAsset(stoi(MediaLibraryDataManagerUtils::GetIdFromUri(albumUri)), to_string(fileAsset.GetId()),
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
        int32_t ret = GrantUriPermission(fileUri, cmd.GetBundleName(), fileAsset.GetPath());
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
    return deleteRows;
}

static void TrashPhotosSendNotify(vector<string> &notifyUris)
{
    auto watch = MediaLibraryNotify::GetInstance();
    int trashAlbumId = watch->GetAlbumIdBySubType(PhotoAlbumSubType::TRASH);
    if (trashAlbumId <= 0) {
        return;
    }

    for (const auto &notifyUri : notifyUris) {
        watch->Notify(notifyUri, NotifyType::NOTIFY_REMOVE);
        watch->Notify(notifyUri, NotifyType::NOTIFY_ALBUM_REMOVE_ASSET);
        watch->Notify(notifyUri, NotifyType::NOTIFY_ALBUM_ADD_ASSERT, trashAlbumId);
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
    ValuesBucket values;
    values.Put(MediaColumn::MEDIA_DATE_TRASHED, MediaFileUtils::UTCTimeSeconds());
    cmd.SetValueBucket(values);
    int32_t updatedRows = rdbStore->Update(values, rdbPredicate);
    if (updatedRows < 0) {
        MEDIA_ERR_LOG("Trash photo failed. Result %{public}d.", updatedRows);
        return E_HAS_DB_ERROR;
    }

    MediaLibraryRdbUtils::UpdateUserAlbumInternal(rdbStore->GetRaw());
    MediaLibraryRdbUtils::UpdateSystemAlbumInternal(rdbStore->GetRaw());
    if (static_cast<size_t>(updatedRows) != notifyUris.size()) {
        MEDIA_WARN_LOG("Try to notify %{public}zu items, but only %{public}d items updated.",
            notifyUris.size(), updatedRows);
    }
    TrashPhotosSendNotify(notifyUris);
    return updatedRows;
}

int32_t MediaLibraryPhotoOperations::UpdateV10(MediaLibraryCommand &cmd)
{
    if (cmd.GetOprnType() == OperationType::TRASH_PHOTO) {
        return TrashPhotos(cmd);
    } else if (cmd.GetOprnType() == OperationType::UPDATE_PENDING) {
        return SetPendingStatus(cmd);
    }

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
    SendHideNotify(cmd, fileAsset->GetId(), extraUri);
    SendModifyUserCommentNotify(cmd, fileAsset->GetId(), extraUri);
    auto watch = MediaLibraryNotify::GetInstance();
    watch->Notify(MediaFileUtils::GetUriByExtrConditions(PhotoColumn::PHOTO_URI_PREFIX, to_string(fileAsset->GetId()),
        extraUri), NotifyType::NOTIFY_UPDATE);
    return rowId;
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
} // namespace Media
} // namespace OHOS

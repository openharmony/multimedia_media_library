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

#include "abs_shared_result_set.h"
#include "file_asset.h"
#include "media_column.h"
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
#include "medialibrary_rdbstore.h"
#include "medialibrary_type_const.h"
#include "medialibrary_uripermission_operations.h"
#include "photo_album_column.h"
#include "photo_map_column.h"
#include "photo_map_operations.h"
#include "rdb_predicates.h"
#include "thumbnail_const.h"
#include "userfile_manager_types.h"
#include "value_object.h"
#include "values_bucket.h"
#include "medialibrary_tracer.h"
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
    shared_ptr<FileAsset> fileAsset = GetFileAssetFromDb(PhotoColumn::MEDIA_ID,
        fileId, cmd.GetOprnObject());
    CHECK_AND_RETURN_RET_LOG(fileAsset != nullptr, E_INVALID_FILEID, "Get fileAsset failed, fileId: %{public}s",
        fileId.c_str());

    int32_t deleteRow = DeletePhoto(fileAsset);
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

shared_ptr<NativeRdb::ResultSet> MediaLibraryPhotoOperations::Query(
    MediaLibraryCommand &cmd, const vector<string> &columns)
{
    RdbPredicates predicates = RdbUtils::ToPredicates(cmd.GetDataSharePred(), PhotoColumn::PHOTOS_TABLE);
    HandleGroupBy(predicates, columns);
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

int32_t MediaLibraryPhotoOperations::Open(MediaLibraryCommand &cmd, const string &mode)
{
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryPhotoOperations::Open");

    string uriString = cmd.GetUriStringWithoutSegment();
    string id = MediaLibraryDataManagerUtils::GetIdFromUri(uriString);
    if (uriString.empty()) {
        return E_INVALID_URI;
    }

    vector<string> columns = {
        PhotoColumn::MEDIA_ID,
        PhotoColumn::MEDIA_FILE_PATH,
        PhotoColumn::MEDIA_TYPE,
        PhotoColumn::MEDIA_TIME_PENDING
    };
    auto fileAsset = GetFileAssetFromDb(PhotoColumn::MEDIA_ID, id,
        OperationObject::FILESYSTEM_PHOTO, columns);
    if (fileAsset == nullptr) {
        MEDIA_ERR_LOG("Failed to obtain path from Database, uri=%{private}s", uriString.c_str());
        return E_INVALID_URI;
    }
    fileAsset->SetUri(uriString);

    if (uriString.find(PhotoColumn::PHOTO_URI_PREFIX) != string::npos) {
        return OpenAsset(fileAsset, mode, MediaLibraryApi::API_10);
    }
    return OpenAsset(fileAsset, mode, cmd.GetApi());
}

int32_t MediaLibraryPhotoOperations::Close(MediaLibraryCommand &cmd)
{
    string strFileId = cmd.GetOprnFileId();
    if (strFileId.empty()) {
        return E_INVALID_FILEID;
    }

    vector<string> columns = {
        PhotoColumn::MEDIA_ID,
        PhotoColumn::MEDIA_FILE_PATH,
        PhotoColumn::MEDIA_TIME_PENDING,
        PhotoColumn::MEDIA_TYPE,
        MediaColumn::MEDIA_DATE_MODIFIED,
        MediaColumn::MEDIA_DATE_ADDED
    };
    auto fileAsset = GetFileAssetFromDb(PhotoColumn::MEDIA_ID, strFileId, cmd.GetOprnObject(), columns);
    if (fileAsset == nullptr) {
        MEDIA_ERR_LOG("Get FileAsset id %{public}s from database failed!", strFileId.c_str());
        return E_INVALID_FILEID;
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

    TransactionOperations transactionOprn;
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

void PhotoMapAddAsset(const int &albumId, const string &assetId)
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

    vector<ValueObject> bindArgs = { albumId, assetId, albumId, assetId, assetId, albumId, PhotoAlbumType::USER, PhotoAlbumSubType::USER_GENERIC };
    int errCode =  MediaLibraryRdbStore::ExecuteForLastInsertedRowId(INSERT_MAP_SQL, bindArgs);
    auto watch = MediaLibraryNotify::GetInstance();
    if (errCode > 0) {
        watch->Notify(PhotoColumn::PHOTO_URI_PREFIX + assetId,
            NotifyType::NOTIFY_ALBUM_ADD_ASSERT, albumId);
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
    if (GetStringFromValuesBucket(values, PhotoColumn::MEDIA_NAME, displayName)) {
        fileAsset.SetDisplayName(displayName);
        isContains = true;
    } else {
        CHECK_AND_RETURN_RET(GetStringFromValuesBucket(values, ASSET_EXTENTION, extention), E_HAS_DB_ERROR);
        if (GetStringFromValuesBucket(values, PhotoColumn::MEDIA_TITLE, title)) {
            displayName = title + "." + extention;
            fileAsset.SetDisplayName(displayName);
            isContains = true;
        }
    }
    int32_t mediaType = 0;
    CHECK_AND_RETURN_RET(GetInt32FromValuesBucket(values, PhotoColumn::MEDIA_TYPE, mediaType),
        E_HAS_DB_ERROR);
    fileAsset.SetMediaType(static_cast<MediaType>(mediaType));
    SetPhotoSubTypeFromCmd(cmd, fileAsset);
    SetCameraShotKeyFromCmd(cmd, fileAsset);
    string albumUri;
    GetStringFromValuesBucket(values, MEDIA_DATA_DB_ALARM_URI, albumUri);
    // Check rootdir and extention
    int32_t errCode = CheckWithType(isContains, displayName, extention, mediaType);
    CHECK_AND_RETURN_RET(errCode == E_OK, errCode);
    TransactionOperations transactionOprn;
    errCode = transactionOprn.Start();
    CHECK_AND_RETURN_RET(errCode == E_OK, errCode);
    errCode = isContains ? SetAssetPathInCreate(fileAsset) : SetAssetPath(fileAsset, extention);
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode,
        "Failed to Solve FileAsset Path and Name, displayName=%{private}s", displayName.c_str());
    int32_t outRow = InsertAssetInDb(cmd, fileAsset);
    CHECK_AND_RETURN_RET_LOG(outRow > 0, errCode, "insert file in db failed, error = %{public}d", outRow);
    if (!albumUri.empty()) {
        string albumId = MediaLibraryDataManagerUtils::GetIdFromUri(albumUri);
        PhotoMapAddAsset(stoi(albumId), to_string(outRow));
    }
    string bdName = cmd.GetBundleName();
    if (!bdName.empty()) {
        errCode = UriPermissionOperations::InsertBundlePermission(outRow, bdName, MEDIA_FILEMODE_READWRITE,
            PhotoColumn::PHOTOS_TABLE);
        CHECK_AND_RETURN_RET_LOG(errCode >= 0, errCode, "InsertBundlePermission failed, err=%{public}d", errCode);
    }
    transactionOprn.Finish();
    return outRow;
}

int32_t MediaLibraryPhotoOperations::DeletePhoto(const shared_ptr<FileAsset> &fileAsset)
{
    string filePath = fileAsset->GetPath();
    CHECK_AND_RETURN_RET_LOG(!filePath.empty(), E_INVALID_PATH, "get file path failed");
    bool res = MediaFileUtils::DeleteFile(filePath);
    CHECK_AND_RETURN_RET_LOG(res, E_HAS_FS_ERROR, "Delete photo file failed, errno: %{public}d", errno);

    // delete thumbnail
    int32_t fileId = fileAsset->GetId();
    InvalidateThumbnail(to_string(fileId), fileAsset->GetMediaType());

    TransactionOperations transactionOprn;
    int32_t errCode = transactionOprn.Start();
    if (errCode != E_OK) {
        return errCode;
    }

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
    watch->Notify(PhotoColumn::PHOTO_URI_PREFIX + to_string(deleteRows), NotifyType::NOTIFY_REMOVE);
    MediaLibraryAlbumOperations::UpdateUserAlbumInternal();
    MediaLibraryAlbumOperations::UpdateSystemAlbumInternal();
    return deleteRows;
}

int32_t MediaLibraryPhotoOperations::TrashPhotos(MediaLibraryCommand &cmd)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        return E_HAS_DB_ERROR;
    }

    NativeRdb::RdbPredicates rdbPredicate = RdbUtils::ToPredicates(cmd.GetDataSharePred(),
        PhotoColumn::PHOTOS_TABLE);
    ValuesBucket values;
    values.Put(MediaColumn::MEDIA_DATE_TRASHED, MediaFileUtils::UTCTimeSeconds());
    cmd.SetValueBucket(values);
    int32_t updatedRows = rdbStore->Update(values, rdbPredicate);
    if (updatedRows < 0) {
        MEDIA_ERR_LOG("Trash photo failed. Result %{public}d.", updatedRows);
        return E_HAS_DB_ERROR;
    }
    for (const string &fileId : cmd.GetAbsRdbPredicates()->GetWhereArgs()) {
        SendTrashNotify(cmd, stoi(fileId));
    }

    MediaLibraryAlbumOperations::UpdateUserAlbumInternal();
    MediaLibraryAlbumOperations::UpdateSystemAlbumInternal();
    return updatedRows;
}

int32_t MediaLibraryPhotoOperations::UpdateV10(MediaLibraryCommand &cmd)
{
    if (cmd.GetOprnType() == OperationType::TRASH_PHOTO) {
        return TrashPhotos(cmd);
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

    // Update if FileAsset.title or FileAsset.displayName is modified
    bool isNameChanged = false;
    int32_t errCode = UpdateFileName(cmd, fileAsset, isNameChanged);
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "Update Photo Name failed, fileName=%{private}s",
        fileAsset->GetDisplayName().c_str());

    TransactionOperations transactionOprn;
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
    SendHideNotify(cmd, fileAsset->GetId());
    auto watch = MediaLibraryNotify::GetInstance();
    watch->Notify(PhotoColumn::PHOTO_URI_PREFIX + to_string(fileAsset->GetId()), NotifyType::NOTIFY_UPDATE);
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

    TransactionOperations transactionOprn;
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
    watch->Notify(PhotoColumn::PHOTO_URI_PREFIX + to_string(fileAsset->GetId()), NotifyType::NOTIFY_UPDATE);
    return rowId;
}
} // namespace Media
} // namespace OHOS

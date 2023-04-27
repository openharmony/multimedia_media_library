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
#include "medialibrary_asset_operations.h"
#include "medialibrary_command.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_notify.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_rdbstore.h"
#include "userfile_manager_types.h"
#include "value_object.h"
using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {

namespace {
int32_t SolvePhotoAssetAlbumInDelete(const shared_ptr<FileAsset> &fileAsset)
{
    // todo: wait a function to get asset in which album

    return E_OK;
}
} // namespace

int32_t MediaLibraryPhotoOperations::Create(MediaLibraryCommand &cmd)
{
    switch (cmd.GetApi()) {
        case MediaLibraryApi::API_10:
            return CreateV10(cmd);
        case MediaLibraryApi::API_OLD:
            MEDIA_ERR_LOG("this api is not realized yet");
            return E_FAIL;
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

shared_ptr<NativeRdb::ResultSet> MediaLibraryPhotoOperations::Query(
    MediaLibraryCommand &cmd, const vector<string> &columns)
{
    switch (cmd.GetApi()) {
        case MediaLibraryApi::API_10:
            return QueryV10(cmd, columns);
        case MediaLibraryApi::API_OLD:
            MEDIA_ERR_LOG("this api is not realized yet");
            return nullptr;
        default:
            MEDIA_ERR_LOG("get api failed");
            return nullptr;
    }
}

int32_t MediaLibraryPhotoOperations::Update(MediaLibraryCommand &cmd)
{
    switch (cmd.GetApi()) {
        case MediaLibraryApi::API_10:
            return UpdateV10(cmd);
        case MediaLibraryApi::API_OLD:
            MEDIA_ERR_LOG("this api is not realized yet");
            return E_FAIL;
        default:
            MEDIA_ERR_LOG("get api failed");
            return E_FAIL;
    }

    return E_OK;
}

int32_t MediaLibraryPhotoOperations::Open(MediaLibraryCommand &cmd, const string &mode)
{
    string uriString = cmd.GetUriStringWithoutSegment();
    string id = MediaLibraryDataManagerUtils::GetIdFromUri(uriString);
    if (uriString.empty()) {
        return E_INVALID_URI;
    }

    vector<string> columns = {
        PhotoColumn::MEDIA_ID,
        PhotoColumn::MEDIA_FILE_PATH,
        PhotoColumn::MEDIA_URI,
        PhotoColumn::MEDIA_TYPE,
        PhotoColumn::MEDIA_TIME_PENDING
    };
    auto fileAsset = GetFileAssetFromDb(PhotoColumn::MEDIA_ID, id,
        OperationObject::FILESYSTEM_PHOTO, columns);
    if (fileAsset == nullptr) {
        MEDIA_ERR_LOG("Failed to obtain path from Database, uri=%{private}s", uriString.c_str());
        return E_INVALID_URI;
    }

    return OpenAsset(fileAsset, mode);
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
        PhotoColumn::MEDIA_URI,
        PhotoColumn::MEDIA_TIME_PENDING,
        PhotoColumn::MEDIA_TYPE
    };
    auto fileAsset = GetFileAssetFromDb(PhotoColumn::MEDIA_ID, strFileId, cmd.GetOprnObject(), columns);
    if (fileAsset == nullptr) {
        MEDIA_ERR_LOG("Get FileAsset id %{public}s from database failed!", strFileId.c_str());
        return E_INVALID_FILEID;
    }

    int32_t errCode = CloseAsset(fileAsset);
    return errCode;
}

int32_t MediaLibraryPhotoOperations::CreateV10(MediaLibraryCommand& cmd)
{
    string displayName;
    int32_t mediaType = 0;
    FileAsset fileAsset;
    ValueObject valueObject;
    ValuesBucket &values = cmd.GetValueBucket();

    CHECK_AND_RETURN_RET(values.GetObject(PhotoColumn::MEDIA_NAME, valueObject), E_HAS_DB_ERROR);
    valueObject.GetString(displayName);
    fileAsset.SetDisplayName(displayName);

    CHECK_AND_RETURN_RET(values.GetObject(PhotoColumn::MEDIA_TYPE, valueObject), E_HAS_DB_ERROR);
    valueObject.GetInt(mediaType);
    fileAsset.SetMediaType(static_cast<MediaType>(mediaType));

    // Check rootdir and extension
    int32_t errCode = CheckDisplayNameWithType(displayName, mediaType);
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode,
        "Failed to Check Dir and Extension, displayName=%{private}s, mediaType=%{public}d",
        displayName.c_str(), mediaType);

    errCode = BeginTransaction();
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("Failed to start transaction, errCode=%{public}d", errCode);
        TransactionRollback();
        return errCode;
    }

    errCode = SetAssetPathInCreate(fileAsset);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("Failed to Solve FileAsset Path and Name, displayName=%{private}s", displayName.c_str());
        TransactionRollback();
        return errCode;
    }

    int32_t outRow = InsertAssetInDb(cmd, fileAsset);
    if (outRow <= 0) {
        MEDIA_ERR_LOG("insert file in db failed, error = %{public}d", outRow);
        TransactionRollback();
        return errCode;
    }

    errCode = TransactionCommit();
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("Failed to commit transaction, errCode=%{public}d", errCode);
        TransactionRollback();
        return errCode;
    }
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

    int32_t errCode = BeginTransaction();
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("Failed to start transaction, errCode=%{public}d", errCode);
        TransactionRollback();
        return errCode;
    }

    // delete file in album
    errCode = SolvePhotoAssetAlbumInDelete(fileAsset);
    if (errCode != E_OK) {
        TransactionRollback();
        return errCode;
    }

    // delete file in db
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::DELETE);
    cmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::MEDIA_ID, to_string(fileId));
    int32_t deleteRows = DeleteAssetInDb(cmd);
    if (deleteRows <= 0) {
        MEDIA_ERR_LOG("Delete photo in database failed, errCode=%{public}d", deleteRows);
        TransactionRollback();
        return E_HAS_DB_ERROR;
    }

    errCode = TransactionCommit();
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("Failed to commit transaction, errCode=%{public}d", errCode);
        TransactionRollback();
        return errCode;
    }
    auto watch = MediaLibraryNotify::GetInstance();
    if (watch != nullptr) {
        watch->Notify(PhotoColumn::PHOTO_URI_PREFIX + to_string(deleteRows), NotifyType::NOTIFY_REMOVE);
    }
    return deleteRows;
}

shared_ptr<NativeRdb::ResultSet> MediaLibraryPhotoOperations::QueryV10(
    MediaLibraryCommand &cmd, const vector<string> &columns)
{
    return QueryFiles(cmd, columns);
}

int32_t MediaLibraryPhotoOperations::UpdateV10(MediaLibraryCommand &cmd)
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

    // Update if FileAsset.path is modified
    if (IsContainsValue(cmd.GetValueBucket(), PhotoColumn::MEDIA_FILE_PATH)) {
        return UpdateAssetPath(cmd, fileAsset);
    }

    // Update if FileAsset.title or FileAsset.displayName is modified
    int32_t errCode = UpdateFileName(cmd, fileAsset);
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "Update Photo Name failed, fileName=%{private}s",
        fileAsset->GetDisplayName().c_str());

    errCode = BeginTransaction();
    if (errCode != E_OK) {
        TransactionRollback();
        return errCode;
    }

    int32_t rowId = UpdateFileInDb(cmd);
    if (rowId < 0) {
        MEDIA_ERR_LOG("Update Photo In database failed, rowId=%{public}d", rowId);
        TransactionRollback();
        return rowId;
    }

    errCode = TransactionCommit();
    if (errCode != E_OK) {
        TransactionRollback();
        return errCode;
    }

    errCode = MediaLibraryObjectUtils::SendTrashNotify(cmd, rowId);
    if (errCode == E_OK) {
        return rowId;
    }
    MediaLibraryObjectUtils::SendFavoriteNotify(cmd, rowId);
    auto watch = MediaLibraryNotify::GetInstance();
    if (watch != nullptr) {
        watch->Notify(PhotoColumn::PHOTO_URI_PREFIX + to_string(rowId), NotifyType::NOTIFY_UPDATE);
    }
    return rowId;
}
} // namespace Media
} // namespace OHOS
/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#define MLOG_TAG "MediaAssetsService"

#include "media_assets_service.h"

#include <string>

#include "media_assets_rdb_operations.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_bundle_manager.h"
#include "medialibrary_facard_operations.h"
#include "media_facard_photos_column.h"
#include "commit_edited_asset_dto.h"
#include "medialibrary_async_worker.h"
#include "medialibrary_vision_operations.h"
#include "medialibrary_rdb_utils.h"
#include "media_analysis_helper.h"
#include "media_file_uri.h"
#include "media_file_utils.h"
#include "medialibrary_tracer.h"
#include "photo_album_column.h"
#include "result_set_utils.h"
#include "dfx_manager.h"
#include "multistages_capture_manager.h"
#include "enhancement_manager.h"
#include "story_album_column.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_photo_operations.h"
#include "permission_utils.h"
#include "medialibrary_notify.h"
#include "medialibrary_command.h"
#include "uri.h"
#include "medialibrary_album_fusion_utils.h"
#include "medialibrary_album_operations.h"

using namespace std;

namespace OHOS::Media {

static void UpdateVisionTableForEdit(AsyncTaskData *taskData)
{
    CHECK_AND_RETURN_LOG(taskData != nullptr, "taskData is nullptr");
    UpdateVisionAsyncTaskData* data = static_cast<UpdateVisionAsyncTaskData*>(taskData);
    CHECK_AND_RETURN_LOG(data != nullptr, "UpdateVisionAsyncTaskData is nullptr");
    string fileId = to_string(data->fileId_);
    MediaAssetsRdbOperations::DeleteFromVisionTables(fileId);
}

MediaAssetsService &MediaAssetsService::GetInstance()
{
    static MediaAssetsService service;
    return service;
}

int32_t MediaAssetsService::RemoveFormInfo(const string& formId)
{
    MEDIA_INFO_LOG("MediaAssetsService::RemoveFormInfo, formId:%{public}s", formId.c_str());
    int32_t deleteRows = this->rdbOperation_.RemoveFormInfo(formId);
    CHECK_AND_RETURN_RET_LOG(deleteRows > 0, E_ERR, "Failed to remove form info");
    return deleteRows;
}

int32_t MediaAssetsService::RemoveGalleryFormInfo(const string& formId)
{
    MEDIA_INFO_LOG("MediaAssetsService::RemoveGalleryFormInfo, formId:%{public}s", formId.c_str());
    return this->rdbOperation_.RemoveGalleryFormInfo(formId);
}

int32_t MediaAssetsService::SaveFormInfo(const FormInfoDto& formInfoDto)
{
    string formId = formInfoDto.formIds.front();
    string fileUri = formInfoDto.fileUris.front();
    return this->rdbOperation_.SaveFormInfo(formId, fileUri);
}

int32_t MediaAssetsService::SaveGalleryFormInfo(const FormInfoDto& formInfoDto)
{
    return this->rdbOperation_.SaveGalleryFormInfo(formInfoDto.formIds, formInfoDto.fileUris);
}

int32_t MediaAssetsService::CommitEditedAsset(const CommitEditedAssetDto& commitEditedAssetDto)
{
    int32_t errCode = this->rdbOperation_.CommitEditInsert(commitEditedAssetDto.editData,
        commitEditedAssetDto.fileId);
    CHECK_AND_RETURN_RET(errCode == E_SUCCESS, errCode);
    shared_ptr<MediaLibraryAsyncWorker> asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    CHECK_AND_RETURN_RET_LOG(asyncWorker != nullptr, E_ERR, "Can not get asyncWorker");
    UpdateVisionAsyncTaskData* taskData =
        new (std::nothrow) UpdateVisionAsyncTaskData(commitEditedAssetDto.fileId);
    CHECK_AND_RETURN_RET_LOG(taskData != nullptr, E_ERR, "Failed to new taskData");
    shared_ptr<MediaLibraryAsyncTask> updateAsyncTask =
        make_shared<MediaLibraryAsyncTask>(UpdateVisionTableForEdit, taskData);
    CHECK_AND_PRINT_LOG(updateAsyncTask != nullptr, "UpdateAnalysisDataForEdit fail");
    asyncWorker->AddTask(updateAsyncTask, true);
    return errCode;
}

int32_t MediaAssetsService::TrashPhotos(const std::vector<std::string> &uris)
{
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::TRASH_PHOTO, MediaLibraryApi::API_10);
    cmd.GetAbsRdbPredicates()->In(PhotoColumn::MEDIA_ID, uris);
    NativeRdb::ValuesBucket values;
    values.Put(MediaColumn::MEDIA_DATE_TRASHED, MediaFileUtils::UTCTimeSeconds());
    cmd.SetValueBucket(values);
    return MediaLibraryPhotoOperations::TrashPhotos(cmd);
}

int32_t MediaAssetsService::DeletePhotosCompleted(const std::vector<std::string> &fileIds)
{
    DataShare::DataSharePredicates predicates;
    predicates.In(PhotoColumn::MEDIA_ID, fileIds);
    return MediaLibraryAlbumOperations::DeletePhotoAssetsCompleted(predicates, false);
}

int32_t MediaAssetsService::CreateAsset(CreateAssetDto& dto)
{
    NativeRdb::ValuesBucket assetInfo;
    assetInfo.PutString(ASSET_EXTENTION, dto.extension);
    assetInfo.PutInt(MediaColumn::MEDIA_TYPE, dto.mediaType);
    assetInfo.PutInt(PhotoColumn::PHOTO_SUBTYPE, dto.photoSubtype);
    if (!dto.title.empty()) {
        assetInfo.PutString(MediaColumn::MEDIA_TITLE, dto.title);
    }
    if (!dto.displayName.empty()) {
        assetInfo.PutString(MediaColumn::MEDIA_NAME, dto.displayName);
    }
    if (!dto.cameraShotKey.empty()) {
        assetInfo.PutString(PhotoColumn::CAMERA_SHOT_KEY, dto.cameraShotKey);
    }

    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::CREATE, MediaLibraryApi::API_10);

    cmd.SetValueBucket(assetInfo);
    cmd.SetBundleName(MediaLibraryBundleManager::GetInstance()->GetClientBundleName());
    int32_t ret = MediaLibraryPhotoOperations::Create(cmd);
    CHECK_AND_RETURN_RET_LOG(ret > 0, ret, "MediaLibraryPhotoOperations::Create failed");
    dto.fileId = ret;
    dto.outUri = cmd.GetResult();
    return E_OK;
}

int32_t MediaAssetsService::CreateAssetForApp(CreateAssetDto& dto)
{
    NativeRdb::ValuesBucket assetInfo;
    assetInfo.PutString(ASSET_EXTENTION, dto.extension);
    assetInfo.PutInt(MediaColumn::MEDIA_TYPE, dto.mediaType);
    assetInfo.PutInt(PhotoColumn::PHOTO_SUBTYPE, dto.photoSubtype);
    assetInfo.PutString(MEDIA_DATA_DB_OWNER_APPID, dto.appId);
    assetInfo.PutString(MEDIA_DATA_DB_PACKAGE_NAME, dto.packageName);
    assetInfo.PutString(MEDIA_DATA_DB_OWNER_PACKAGE, dto.bundleName);
    if (!dto.title.empty()) {
        assetInfo.PutString(MediaColumn::MEDIA_TITLE, dto.title);
    }

    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::CREATE, MediaLibraryApi::API_10);

    cmd.SetValueBucket(assetInfo);
    cmd.SetBundleName(MediaLibraryBundleManager::GetInstance()->GetClientBundleName());
    int32_t ret = MediaLibraryPhotoOperations::Create(cmd);
    CHECK_AND_RETURN_RET_LOG(ret > 0, ret, "MediaLibraryPhotoOperations::Create failed");
    dto.fileId = ret;
    dto.outUri = cmd.GetResult();
    return E_OK;
}

int32_t MediaAssetsService::CreateAssetForAppWithAlbum(CreateAssetDto& dto)
{
    if (!this->rdbOperation_.QueryAlbumIdIfExists(dto.ownerAlbumId)) {
        MEDIA_ERR_LOG("Invalid ownerAlbumId:%{public}s", dto.ownerAlbumId.c_str());
        return -EINVAL;
    }

    NativeRdb::ValuesBucket assetInfo;
    assetInfo.PutString(ASSET_EXTENTION, dto.extension);
    assetInfo.PutInt(MediaColumn::MEDIA_TYPE, dto.mediaType);
    assetInfo.PutInt(PhotoColumn::PHOTO_SUBTYPE, dto.photoSubtype);
    assetInfo.PutString(MEDIA_DATA_DB_OWNER_APPID, dto.appId);
    assetInfo.PutString(MEDIA_DATA_DB_PACKAGE_NAME, dto.packageName);
    assetInfo.PutString(MEDIA_DATA_DB_OWNER_PACKAGE, dto.bundleName);
    assetInfo.PutString(PhotoColumn::PHOTO_OWNER_ALBUM_ID, dto.ownerAlbumId);
    if (!dto.title.empty()) {
        assetInfo.PutString(MediaColumn::MEDIA_TITLE, dto.title);
    }

    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::CREATE, MediaLibraryApi::API_10);

    cmd.SetValueBucket(assetInfo);
    cmd.SetApiParam("tokenId", to_string(dto.tokenId));
    cmd.SetBundleName(MediaLibraryBundleManager::GetInstance()->GetClientBundleName());
    int32_t ret = MediaLibraryPhotoOperations::Create(cmd);
    CHECK_AND_RETURN_RET_LOG(ret > 0, ret, "MediaLibraryPhotoOperations::Create failed");
    dto.fileId = ret;
    dto.outUri = cmd.GetResult();
    return E_OK;
}

int32_t MediaAssetsService::CloneAsset(const CloneAssetDto& cloneAssetDto)
{
    MEDIA_INFO_LOG("MediaAssetsService::CloneAsset, fileId:%{public}d, title:%{public}s",
        cloneAssetDto.fileId, cloneAssetDto.title.c_str());

    int32_t fileId = cloneAssetDto.fileId;
    string title = cloneAssetDto.title;
    return MediaLibraryAlbumFusionUtils::CloneSingleAsset(fileId, title);
}

int32_t MediaAssetsService::RevertToOriginal(const RevertToOriginalDto& revertToOriginalDto)
{
    int32_t fileId = revertToOriginalDto.fileId;
    MEDIA_INFO_LOG("MediaAssetsService::RevertToOriginal, fileId:%{public}d", fileId);

    int32_t errCode = this->rdbOperation_.RevertToOrigin(fileId);
    if (errCode == E_SUCCESS) {
        string fileUri = revertToOriginalDto.fileUri;
        Uri uri(fileUri);
        MediaLibraryCommand cmdEditCommit(uri);
        MediaLibraryVisionOperations::EditCommitOperation(cmdEditCommit);
    }
    return errCode;
}
} // namespace OHOS::Media
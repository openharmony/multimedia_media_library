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
#include "multistages_capture_request_task_manager.h"
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
#include "enhancement_manager.h"
#include "rdb_utils.h"
#include "media_app_uri_permission_column.h"
#include "media_app_uri_sensitive_column.h"

using namespace std;
using namespace OHOS::RdbDataShareAdapter;

namespace OHOS::Media {

const int32_t YES = 1;
const int32_t NO = 0;
const std::string SET_LOCATION_KEY = "set_location";
const std::string SET_LOCATION_VALUE = "1";

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
    DataShare::DataSharePredicates predicates;
    predicates.In(PhotoColumn::MEDIA_ID, uris);
    cmd.SetDataSharePred(predicates);
    NativeRdb::ValuesBucket values;
    values.Put(MediaColumn::MEDIA_DATE_TRASHED, MediaFileUtils::UTCTimeSeconds());
    cmd.SetValueBucket(values);
    return MediaLibraryPhotoOperations::TrashPhotos(cmd);
}

int32_t MediaAssetsService::DeletePhotos(const std::vector<std::string> &uris)
{
    DataShare::DataSharePredicates predicates;
    predicates.In(MediaColumn::MEDIA_ID, uris);
    return MediaLibraryAlbumOperations::DeletePhotoAssets(predicates, false, false);
}

int32_t MediaAssetsService::DeletePhotosCompleted(const std::vector<std::string> &fileIds)
{
    DataShare::DataSharePredicates predicates;
    predicates.In(PhotoColumn::MEDIA_ID, fileIds);
    return MediaLibraryAlbumOperations::DeletePhotoAssetsCompleted(predicates, false);
}

static std::string GetLocalDeviceName()
{
#ifdef DISTRIBUTED
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    auto &deviceManager = OHOS::DistributedHardware::DeviceManager::GetInstance();
    int32_t ret = deviceManager.GetLocalDeviceInfo(BUNDLE_NAME, deviceInfo);
    if (ret == 0) {
        return deviceInfo.deviceName;
    }
    MEDIA_ERR_LOG("GetLocalDeviceInfo ret = %{public}d", ret);
#endif
    return "";
}

static std::string GetClientBundleName()
{
    string bundleName = MediaLibraryBundleManager::GetInstance()->GetClientBundleName();
    if (bundleName.empty()) {
        MEDIA_ERR_LOG("GetClientBundleName failed");
    }
    return bundleName;
}

int32_t MediaAssetsService::AssetChangeSetFavorite(const int32_t fileId, const bool favorite)
{
    DataShare::DataSharePredicates predicate;
    predicate.EqualTo(PhotoColumn::MEDIA_ID, std::to_string(fileId));

    NativeRdb::ValuesBucket values;
    values.PutInt(PhotoColumn::MEDIA_IS_FAV, favorite ? YES : NO);

    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::UPDATE, MediaLibraryApi::API_10);

    cmd.SetValueBucket(values);
    cmd.SetDataSharePred(predicate);
    NativeRdb::RdbPredicates rdbPredicate = RdbUtils::ToPredicates(predicate, cmd.GetTableName());
    cmd.GetAbsRdbPredicates()->SetWhereClause(rdbPredicate.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(rdbPredicate.GetWhereArgs());
    return MediaLibraryPhotoOperations::Update(cmd);
}

int32_t MediaAssetsService::AssetChangeSetHidden(const std::string &uri, const bool hidden)
{
    DataShare::DataSharePredicates predicate;
    vector<string> uris{uri};
    predicate.In(PhotoColumn::MEDIA_ID, uris);

    NativeRdb::ValuesBucket values;
    values.PutInt(PhotoColumn::MEDIA_HIDDEN, hidden ? YES : NO);

    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::HIDE, MediaLibraryApi::API_10);

    cmd.SetValueBucket(values);
    cmd.SetDataSharePred(predicate);
    NativeRdb::RdbPredicates rdbPredicate = RdbUtils::ToPredicates(predicate, cmd.GetTableName());
    cmd.GetAbsRdbPredicates()->SetWhereClause(rdbPredicate.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(rdbPredicate.GetWhereArgs());
    return MediaLibraryPhotoOperations::Update(cmd);
}

int32_t MediaAssetsService::AssetChangeSetUserComment(const int32_t fileId, const std::string &userComment)
{
    DataShare::DataSharePredicates predicate;
    predicate.EqualTo(PhotoColumn::MEDIA_ID, fileId);

    NativeRdb::ValuesBucket values;
    values.Put(PhotoColumn::PHOTO_USER_COMMENT, userComment);

    MediaLibraryCommand cmd(
        OperationObject::FILESYSTEM_PHOTO, OperationType::SET_USER_COMMENT, MediaLibraryApi::API_10);

    cmd.SetValueBucket(values);
    cmd.SetDataSharePred(predicate);
    NativeRdb::RdbPredicates rdbPredicate = RdbUtils::ToPredicates(predicate, cmd.GetTableName());
    cmd.GetAbsRdbPredicates()->SetWhereClause(rdbPredicate.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(rdbPredicate.GetWhereArgs());
    return MediaLibraryPhotoOperations::Update(cmd);
}

int32_t MediaAssetsService::AssetChangeSetLocation(const SetLocationDto &dto)
{
    NativeRdb::ValuesBucket values;
    values.Put(PhotoColumn::MEDIA_ID, dto.fileId);
    values.Put(PhotoColumn::MEDIA_FILE_PATH, dto.path);
    values.Put(PhotoColumn::PHOTO_LATITUDE, dto.latitude);
    values.Put(PhotoColumn::PHOTO_LONGITUDE, dto.longitude);
    MultiStagesPhotoCaptureManager::UpdateLocation(values, false);
    return E_OK;
}

int32_t MediaAssetsService::AssetChangeSetTitle(const int32_t fileId, const std::string &title)
{
    DataShare::DataSharePredicates predicate;
    predicate.EqualTo(PhotoColumn::MEDIA_ID, fileId);

    NativeRdb::ValuesBucket values;
    values.Put(PhotoColumn::MEDIA_TITLE, title);

    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::UPDATE, MediaLibraryApi::API_10);

    cmd.SetValueBucket(values);
    cmd.SetDataSharePred(predicate);
    NativeRdb::RdbPredicates rdbPredicate = RdbUtils::ToPredicates(predicate, cmd.GetTableName());
    cmd.GetAbsRdbPredicates()->SetWhereClause(rdbPredicate.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(rdbPredicate.GetWhereArgs());
    return MediaLibraryPhotoOperations::Update(cmd);
}

int32_t MediaAssetsService::AssetChangeSetEditData(const NativeRdb::ValuesBucket &values)
{
    MediaLibraryCommand cmd(
        OperationObject::FILESYSTEM_PHOTO, OperationType::ADD_FILTERS, values, MediaLibraryApi::API_10);

    string clientBundle = MediaLibraryBundleManager::GetInstance()->GetClientBundleName();
    if (clientBundle.empty()) {
        MEDIA_ERR_LOG("GetClientBundleName failed");
    } else {
        cmd.SetBundleName(clientBundle);
    }

#ifdef DISTRIBUTED
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    auto &deviceManager = OHOS::DistributedHardware::DeviceManager::GetInstance();
    int32_t ret = deviceManager.GetLocalDeviceInfo(BUNDLE_NAME, deviceInfo);
    if (ret < 0) {
        MEDIA_ERR_LOG("GetLocalDeviceInfo ret = %{public}d", ret);
    } else {
        cmd.SetDeviceName(deviceInfo.deviceName);
    }
#endif

    return MediaLibraryPhotoOperations::AddFilters(cmd);
}

int32_t MediaAssetsService::AssetChangeSubmitCache(SubmitCacheDto &dto)
{
    MEDIA_INFO_LOG("SubmitCache isWriteGpsAdvanced: %{public}d", dto.isWriteGpsAdvanced);

    MediaLibraryCommand cmd(
        OperationObject::FILESYSTEM_PHOTO, OperationType::SUBMIT_CACHE, dto.values, MediaLibraryApi::API_10);
    if (dto.isWriteGpsAdvanced) {
        cmd.SetApiParam(SET_LOCATION_KEY, SET_LOCATION_VALUE);
    }

    string clientBundle = MediaLibraryBundleManager::GetInstance()->GetClientBundleName();
    if (clientBundle.empty()) {
        MEDIA_ERR_LOG("GetClientBundleName failed");
    } else {
        cmd.SetBundleName(clientBundle);
    }

#ifdef DISTRIBUTED
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    auto &deviceManager = OHOS::DistributedHardware::DeviceManager::GetInstance();
    int32_t ret = deviceManager.GetLocalDeviceInfo(BUNDLE_NAME, deviceInfo);
    if (ret < 0) {
        MEDIA_ERR_LOG("GetLocalDeviceInfo ret = %{public}d", ret);
    } else {
        cmd.SetDeviceName(deviceInfo.deviceName);
    }
#endif

    int32_t ret = MediaLibraryPhotoOperations::SubmitCache(cmd);
    CHECK_AND_RETURN_RET_LOG(ret >= 0, ret, "MediaLibraryPhotoOperations::SubmitCache failed");
    dto.fileId = ret;
    dto.outUri = cmd.GetResult();
    return E_OK;
}

int32_t MediaAssetsService::AssetChangeCreateAsset(AssetChangeCreateAssetDto &dto)
{
    MediaLibraryCommand cmd(
        OperationObject::FILESYSTEM_PHOTO, OperationType::CREATE, dto.values, MediaLibraryApi::API_10);

    string clientBundle = MediaLibraryBundleManager::GetInstance()->GetClientBundleName();
    if (clientBundle.empty()) {
        MEDIA_ERR_LOG("GetClientBundleName failed");
    } else {
        cmd.SetBundleName(clientBundle);
    }

#ifdef DISTRIBUTED
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    auto &deviceManager = OHOS::DistributedHardware::DeviceManager::GetInstance();
    int32_t ret = deviceManager.GetLocalDeviceInfo(BUNDLE_NAME, deviceInfo);
    if (ret < 0) {
        MEDIA_ERR_LOG("GetLocalDeviceInfo ret = %{public}d", ret);
    } else {
        cmd.SetDeviceName(deviceInfo.deviceName);
    }
#endif

    int32_t ret = MediaLibraryPhotoOperations::Create(cmd);
    CHECK_AND_RETURN_RET_LOG(ret > 0, ret, "MediaLibraryPhotoOperations::Create failed");
    dto.fileId = ret;
    dto.outUri = cmd.GetResult();
    return E_OK;
}

int32_t MediaAssetsService::AssetChangeAddImage(AddImageDto &dto)
{
    DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause(PhotoColumn::MEDIA_ID + " = ? ");
    predicates.SetWhereArgs({to_string(dto.fileId)});

    NativeRdb::ValuesBucket values;
    values.Put(PhotoColumn::MEDIA_ID, dto.fileId);
    values.Put(PhotoColumn::PHOTO_ID, dto.photoId);
    values.Put(PhotoColumn::PHOTO_DEFERRED_PROC_TYPE, dto.deferredProcType);

    MediaLibraryCommand cmd(
        OperationObject::PAH_MULTISTAGES_CAPTURE, OperationType::ADD_IMAGE, MediaLibraryApi::API_10);

    cmd.SetValueBucket(values);
    cmd.SetDataSharePred(predicates);
    NativeRdb::RdbPredicates rdbPredicate = RdbUtils::ToPredicates(predicates, cmd.GetTableName());
    cmd.GetAbsRdbPredicates()->SetWhereClause(rdbPredicate.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(rdbPredicate.GetWhereArgs());
    MultiStagesPhotoCaptureManager::GetInstance().AddImage(cmd);
    return E_OK;
}

int32_t MediaAssetsService::SetCameraShotKey(const int32_t fileId, const std::string &cameraShotKey)
{
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::UPDATE, MediaLibraryApi::API_10);

    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PhotoColumn::MEDIA_ID, to_string(fileId));

    NativeRdb::ValuesBucket values;
    values.Put(PhotoColumn::CAMERA_SHOT_KEY, cameraShotKey);

    cmd.SetValueBucket(values);
    cmd.SetDataSharePred(predicates);
    NativeRdb::RdbPredicates rdbPredicate = RdbUtils::ToPredicates(predicates, cmd.GetTableName());
    cmd.GetAbsRdbPredicates()->SetWhereClause(rdbPredicate.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(rdbPredicate.GetWhereArgs());
    return MediaLibraryPhotoOperations::UpdateFileAsset(cmd);
}

int32_t MediaAssetsService::SaveCameraPhoto(const SaveCameraPhotoDto &dto)
{
    MediaLibraryCommand cmd(
        OperationObject::FILESYSTEM_PHOTO, OperationType::SAVE_CAMERA_PHOTO, MediaLibraryApi::API_10);

    if (dto.discardHighQualityPhoto) {
        string photoId = MultiStagesCaptureRequestTaskManager::GetProcessingPhotoId(dto.fileId);
        MEDIA_INFO_LOG("fileId: %{public}d, photoId: %{public}s", dto.fileId, photoId.c_str());
        MultiStagesPhotoCaptureManager::GetInstance().CancelProcessRequest(photoId);
        MultiStagesPhotoCaptureManager::GetInstance().RemoveImage(photoId, false);

        cmd.SetApiParam(PhotoColumn::PHOTO_DIRTY, to_string(static_cast<int32_t>(DirtyType::TYPE_NEW)));
    }
    cmd.SetApiParam(MEDIA_OPERN_KEYWORD, to_string(dto.needScan));
    cmd.SetApiParam(PhotoColumn::MEDIA_FILE_PATH, dto.path);
    cmd.SetApiParam(PhotoColumn::MEDIA_ID, to_string(dto.fileId));
    cmd.SetApiParam(PhotoColumn::PHOTO_SUBTYPE, to_string(dto.photoSubType));
    cmd.SetApiParam(IMAGE_FILE_TYPE, to_string(dto.imageFileType));
    NativeRdb::ValuesBucket values;
    if (dto.supportedWatermarkType != INT32_MIN) {
        values.Put(PhotoColumn::SUPPORTED_WATERMARK_TYPE, dto.supportedWatermarkType);
    }
    if (dto.cameraShotKey != "NotSet") {
        values.Put(PhotoColumn::CAMERA_SHOT_KEY, dto.cameraShotKey);
    }

    values.Put(PhotoColumn::PHOTO_IS_TEMP, false);
    cmd.SetValueBucket(values);
    return MediaLibraryPhotoOperations::SaveCameraPhoto(cmd);
}

int32_t MediaAssetsService::DiscardCameraPhoto(const int32_t fileId)
{
    MediaLibraryCommand cmd(
        OperationObject::FILESYSTEM_PHOTO, OperationType::DISCARD_CAMERA_PHOTO, MediaLibraryApi::API_10);
    cmd.SetApiParam(PhotoColumn::MEDIA_ID, to_string(fileId));

    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PhotoColumn::MEDIA_ID, to_string(fileId));
    predicates.EqualTo(PhotoColumn::PHOTO_IS_TEMP, "1");  // only temp camera photo can be discarded
    cmd.SetDataSharePred(predicates);

    NativeRdb::ValuesBucket values;
    values.Put(PhotoColumn::PHOTO_IS_TEMP, true);
    cmd.SetValueBucket(values);
    return MediaLibraryPhotoOperations::DiscardCameraPhoto(cmd);
}

int32_t MediaAssetsService::SetEffectMode(const int32_t fileId, const int32_t effectMode)
{
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::UPDATE, MediaLibraryApi::API_10);

    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PhotoColumn::MEDIA_ID, to_string(fileId));

    NativeRdb::ValuesBucket values;
    values.Put(PhotoColumn::MOVING_PHOTO_EFFECT_MODE, effectMode);

    cmd.SetValueBucket(values);
    cmd.SetDataSharePred(predicates);
    NativeRdb::RdbPredicates rdbPredicate = RdbUtils::ToPredicates(predicates, cmd.GetTableName());
    cmd.GetAbsRdbPredicates()->SetWhereClause(rdbPredicate.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(rdbPredicate.GetWhereArgs());
    return MediaLibraryPhotoOperations::UpdateFileAsset(cmd);
}

int32_t MediaAssetsService::SetOrientation(const int32_t fileId, const int32_t orientation)
{
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::UPDATE, MediaLibraryApi::API_10);

    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PhotoColumn::MEDIA_ID, to_string(fileId));

    NativeRdb::ValuesBucket values;
    values.Put(PhotoColumn::PHOTO_ORIENTATION, orientation);

    cmd.SetValueBucket(values);
    cmd.SetDataSharePred(predicates);
    NativeRdb::RdbPredicates rdbPredicate = RdbUtils::ToPredicates(predicates, cmd.GetTableName());
    cmd.GetAbsRdbPredicates()->SetWhereClause(rdbPredicate.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(rdbPredicate.GetWhereArgs());
    return MediaLibraryPhotoOperations::UpdateFileAsset(cmd);
}

int32_t MediaAssetsService::SetVideoEnhancementAttr(
    const int32_t fileId, const std::string &photoId, const std::string &path)
{
    MEDIA_DEBUG_LOG("photoId:%{public}s, fileId:%{public}d, path:%{public}s", photoId.c_str(), fileId, path.c_str());
    MultiStagesVideoCaptureManager::GetInstance().AddVideo(photoId, to_string(fileId), path);
    return E_OK;
}

int32_t MediaAssetsService::SetSupportedWatermarkType(const int32_t fileId, const int32_t watermarkType)
{
    MediaLibraryCommand cmd(
        OperationObject::FILESYSTEM_PHOTO, OperationType::UPDATE_SUPPORTED_WATERMARK_TYPE, MediaLibraryApi::API_10);

    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PhotoColumn::MEDIA_ID, to_string(fileId));

    NativeRdb::ValuesBucket values;
    values.Put(PhotoColumn::SUPPORTED_WATERMARK_TYPE, watermarkType);

    cmd.SetValueBucket(values);
    cmd.SetDataSharePred(predicates);
    NativeRdb::RdbPredicates rdbPredicate = RdbUtils::ToPredicates(predicates, cmd.GetTableName());
    cmd.GetAbsRdbPredicates()->SetWhereClause(rdbPredicate.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(rdbPredicate.GetWhereArgs());
    return MediaLibraryPhotoOperations::UpdateSupportedWatermarkType(cmd);
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

static void ConvertToString(const vector<int32_t> &fileIds, std::vector<std::string> &strIds)
{
    for (int32_t fileId : fileIds) {
        strIds.push_back(to_string(fileId));
    }
}

int32_t MediaAssetsService::SetAssetTitle(int32_t fileId, const std::string &title)
{
    NativeRdb::ValuesBucket assetInfo;
    assetInfo.PutString(PhotoColumn::MEDIA_TITLE, title);

    DataShare::DataSharePredicates predicate;
    predicate.EqualTo(PhotoColumn::MEDIA_ID, std::to_string(fileId));
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::UPDATE, MediaLibraryApi::API_10);

    cmd.SetValueBucket(assetInfo);
    cmd.SetDataSharePred(predicate);
    NativeRdb::RdbPredicates rdbPredicate = RdbUtils::ToPredicates(predicate, cmd.GetTableName());
    cmd.GetAbsRdbPredicates()->SetWhereClause(rdbPredicate.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(rdbPredicate.GetWhereArgs());
    return MediaLibraryPhotoOperations::Update(cmd);
}

int32_t MediaAssetsService::SetAssetPending(int32_t fileId, int32_t pending)
{
    DataShare::DataSharePredicates predicate;
    predicate.EqualTo(PhotoColumn::MEDIA_ID, std::to_string(fileId));

    NativeRdb::ValuesBucket assetInfo;
    assetInfo.PutInt(PhotoColumn::MEDIA_TIME_PENDING, pending);

    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::UPDATE_PENDING, MediaLibraryApi::API_10);

    cmd.SetValueBucket(assetInfo);
    cmd.SetDataSharePred(predicate);
    NativeRdb::RdbPredicates rdbPredicate = RdbUtils::ToPredicates(predicate, cmd.GetTableName());
    cmd.GetAbsRdbPredicates()->SetWhereClause(rdbPredicate.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(rdbPredicate.GetWhereArgs());
    return MediaLibraryPhotoOperations::Update(cmd);
}

int32_t MediaAssetsService::SetAssetsFavorite(const std::vector<int32_t> &fileIds, int32_t favorite)
{
    std::vector<std::string> strIds;
    ConvertToString(fileIds, strIds);
    std::vector<std::string> uris;
    this->rdbOperation_.QueryAssetsUri(strIds, uris);

    DataShare::DataSharePredicates predicate;
    predicate.In(PhotoColumn::MEDIA_ID, uris);

    NativeRdb::ValuesBucket assetInfo;
    assetInfo.PutInt(PhotoColumn::MEDIA_IS_FAV, favorite);

    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::BATCH_UPDATE_FAV,
        MediaLibraryApi::API_10);

    cmd.SetValueBucket(assetInfo);
    cmd.SetDataSharePred(predicate);
    NativeRdb::RdbPredicates rdbPredicate = RdbUtils::ToPredicates(predicate, cmd.GetTableName());
    cmd.GetAbsRdbPredicates()->SetWhereClause(rdbPredicate.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(rdbPredicate.GetWhereArgs());
    return MediaLibraryPhotoOperations::Update(cmd);
}

int32_t MediaAssetsService::SetAssetsHiddenStatus(const std::vector<int32_t> &fileIds, int32_t hiddenStatus)
{
    std::vector<std::string> strIds;
    ConvertToString(fileIds, strIds);
    std::vector<std::string> uris;
    this->rdbOperation_.QueryAssetsUri(strIds, uris);

    DataShare::DataSharePredicates predicate;
    predicate.In(PhotoColumn::MEDIA_ID, uris);

    NativeRdb::ValuesBucket assetInfo;
    assetInfo.PutInt(PhotoColumn::MEDIA_HIDDEN, hiddenStatus);

    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::HIDE, MediaLibraryApi::API_10);

    cmd.SetValueBucket(assetInfo);
    cmd.SetDataSharePred(predicate);
    NativeRdb::RdbPredicates rdbPredicate = RdbUtils::ToPredicates(predicate, cmd.GetTableName());
    cmd.GetAbsRdbPredicates()->SetWhereClause(rdbPredicate.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(rdbPredicate.GetWhereArgs());
    return MediaLibraryPhotoOperations::Update(cmd);
}

int32_t MediaAssetsService::SetAssetsRecentShowStatus(const std::vector<int32_t> &fileIds, int32_t recentShowStatus)
{
    std::vector<std::string> strIds;
    ConvertToString(fileIds, strIds);
    std::vector<std::string> uris;
    this->rdbOperation_.QueryAssetsUri(strIds, uris);

    DataShare::DataSharePredicates predicate;
    predicate.In(PhotoColumn::MEDIA_ID, uris);

    NativeRdb::ValuesBucket assetInfo;
    assetInfo.PutInt(PhotoColumn::PHOTO_IS_RECENT_SHOW, recentShowStatus);

    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::BATCH_UPDATE_RECENT_SHOW,
        MediaLibraryApi::API_10);

    cmd.SetValueBucket(assetInfo);
    cmd.SetDataSharePred(predicate);
    NativeRdb::RdbPredicates rdbPredicate = RdbUtils::ToPredicates(predicate, cmd.GetTableName());
    cmd.GetAbsRdbPredicates()->SetWhereClause(rdbPredicate.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(rdbPredicate.GetWhereArgs());
    return MediaLibraryPhotoOperations::Update(cmd);
}

int32_t MediaAssetsService::SetAssetsUserComment(const std::vector<int32_t> &fileIds, const std::string &userComment)
{
    std::vector<std::string> strIds;
    ConvertToString(fileIds, strIds);
    std::vector<std::string> uris;
    this->rdbOperation_.QueryAssetsUri(strIds, uris);

    DataShare::DataSharePredicates predicate;
    predicate.In(PhotoColumn::MEDIA_ID, uris);

    NativeRdb::ValuesBucket assetInfo;
    assetInfo.Put(PhotoColumn::PHOTO_USER_COMMENT, userComment);

    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::BATCH_UPDATE_USER_COMMENT,
        MediaLibraryApi::API_10);

    cmd.SetValueBucket(assetInfo);
    cmd.SetDataSharePred(predicate);
    NativeRdb::RdbPredicates rdbPredicate = RdbUtils::ToPredicates(predicate, cmd.GetTableName());
    cmd.GetAbsRdbPredicates()->SetWhereClause(rdbPredicate.GetWhereClause());
    cmd.GetAbsRdbPredicates()->SetWhereArgs(rdbPredicate.GetWhereArgs());
    return MediaLibraryPhotoOperations::Update(cmd);
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

int32_t MediaAssetsService::SubmitCloudEnhancementTasks(const CloudEnhancementDto& cloudEnhancementDto)
{
    MediaLibraryCommand cmd(PhotoColumn::PHOTOS_TABLE);
    DataShare::DataSharePredicates predicate;
    predicate.In(MediaColumn::MEDIA_ID, cloudEnhancementDto.fileUris);
    cmd.SetDataSharePred(predicate);
#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
    return EnhancementManager::GetInstance().HandleAddOperation(cmd, cloudEnhancementDto.hasCloudWatermark,
        cloudEnhancementDto.triggerMode);
#else
    MEDIA_ERR_LOG("not supply cloud enhancement service");
    return E_ERR;
#endif
}

int32_t MediaAssetsService::PrioritizeCloudEnhancementTask(const CloudEnhancementDto& cloudEnhancementDto)
{
    MediaLibraryCommand cmd(PhotoColumn::PHOTOS_TABLE);
    DataShare::DataSharePredicates predicate;
    predicate.EqualTo(MediaColumn::MEDIA_ID, cloudEnhancementDto.fileUris.front());
    cmd.SetDataSharePred(predicate);
    return EnhancementManager::GetInstance().HandlePrioritizeOperation(cmd);
}

int32_t MediaAssetsService::CancelCloudEnhancementTasks(const CloudEnhancementDto& cloudEnhancementDto)
{
    MediaLibraryCommand cmd(PhotoColumn::PHOTOS_TABLE);
    DataShare::DataSharePredicates predicate;
    predicate.In(MediaColumn::MEDIA_ID, cloudEnhancementDto.fileUris);
    cmd.SetDataSharePred(predicate);
    return EnhancementManager::GetInstance().HandleCancelOperation(cmd);
}

int32_t MediaAssetsService::CancelAllCloudEnhancementTasks()
{
    return EnhancementManager::GetInstance().HandleCancelAllOperation();
}

int32_t MediaAssetsService::GrantPhotoUriPermission(const GrantUriPermissionDto &grantUriPermissionDto)
{
    MEDIA_INFO_LOG("enter MediaAssetsService::GrantPhotoUriPermission");
    NativeRdb::ValuesBucket values;
    values.PutLong(AppUriPermissionColumn::TARGET_TOKENID, grantUriPermissionDto.tokenId);
    values.PutLong(AppUriPermissionColumn::SOURCE_TOKENID, grantUriPermissionDto.srcTokenId);
    values.PutInt(AppUriPermissionColumn::FILE_ID, grantUriPermissionDto.fileId);
    values.PutInt(AppUriPermissionColumn::PERMISSION_TYPE, grantUriPermissionDto.permissionType);
    values.PutInt(AppUriSensitiveColumn::HIDE_SENSITIVE_TYPE, grantUriPermissionDto.hideSensitiveType);
    values.PutInt(AppUriPermissionColumn::URI_TYPE, grantUriPermissionDto.uriType);
    MediaLibraryCommand grantUriPermCmd(values);
    int32_t errCode = this->rdbOperation_.GrantPhotoUriPermission(grantUriPermCmd);
    MEDIA_INFO_LOG("MediaAssetsService::GrantPhotoUriPermission ret:%{public}d", errCode);
    return errCode;
}

int32_t MediaAssetsService::GrantPhotoUrisPermission(const GrantUrisPermissionDto &grantUrisPermissionDto)
{
    MEDIA_INFO_LOG("enter MediaAssetsService::GrantPhotoUrisPermission");
    std::vector<DataShare::DataShareValuesBucket> values;
    for (int32_t fileId : grantUrisPermissionDto.fileIds) {
        DataShare::DataShareValuesBucket value;
        value.Put(AppUriPermissionColumn::TARGET_TOKENID, grantUrisPermissionDto.tokenId);
        value.Put(AppUriPermissionColumn::SOURCE_TOKENID, grantUrisPermissionDto.srcTokenId);
        value.Put(AppUriPermissionColumn::FILE_ID, fileId);
        value.Put(AppUriPermissionColumn::PERMISSION_TYPE, grantUrisPermissionDto.permissionType);
        value.Put(AppUriSensitiveColumn::HIDE_SENSITIVE_TYPE, grantUrisPermissionDto.hideSensitiveType);
        value.Put(AppUriPermissionColumn::URI_TYPE, grantUrisPermissionDto.uriType);
        values.push_back(value);
    }
    string uri = "datashare:///media/app_uri_permission_operation/create?api_version=10";
    Uri createUri(uri);
    MediaLibraryCommand grantUrisPermCmd(createUri);
    // Use values only
    int32_t errCode = this->rdbOperation_.GrantPhotoUrisPermission(grantUrisPermCmd, values);
    MEDIA_INFO_LOG("MediaAssetsService::GrantPhotoUrisPermission ret:%{public}d", errCode);
    return errCode;
}

int32_t MediaAssetsService::CancelPhotoUriPermission(const CancelUriPermissionDto &cancelUriPermissionDto)
{
    MEDIA_INFO_LOG("enter MediaAssetsService::CancelPhotoUriPermission");
    std::string uriPermissionTabel = "UriPermission";
    NativeRdb::RdbPredicates rdbPredicate(uriPermissionTabel);
    rdbPredicate.EqualTo(AppUriPermissionColumn::TARGET_TOKENID, cancelUriPermissionDto.tokenId);
    rdbPredicate.EqualTo(AppUriPermissionColumn::SOURCE_TOKENID, cancelUriPermissionDto.srcTokenId);
    rdbPredicate.EqualTo(AppUriPermissionColumn::FILE_ID, cancelUriPermissionDto.fileId);
    rdbPredicate.EqualTo(AppUriPermissionColumn::PERMISSION_TYPE, cancelUriPermissionDto.permissionType);
    rdbPredicate.EqualTo(AppUriPermissionColumn::URI_TYPE, cancelUriPermissionDto.uriType);
    int32_t errCode = this->rdbOperation_.CancelPhotoUriPermission(rdbPredicate);
    MEDIA_INFO_LOG("MediaAssetsService::CancelPhotoUriPermission ret:%{public}d", errCode);
    return errCode;
}

int32_t MediaAssetsService::StartThumbnailCreationTask(
    const StartThumbnailCreationTaskDto &startThumbnailCreationTaskDto)
{
    MEDIA_INFO_LOG(
        "enter MediaAssetsService::StartThumbnailCreationTask, %{public}d", startThumbnailCreationTaskDto.requestId);
    NativeRdb::RdbPredicates rdbPredicate = OHOS::RdbDataShareAdapter::RdbUtils::ToPredicates(
        startThumbnailCreationTaskDto.predicates, PhotoColumn::PHOTOS_TABLE);
    int32_t errCode =
        this->rdbOperation_.StartThumbnailCreationTask(rdbPredicate, startThumbnailCreationTaskDto.requestId);
    MEDIA_INFO_LOG("MediaAssetsService::startThumbnailCreationTaskDto ret:%{public}d", errCode);
    return errCode;
}

int32_t MediaAssetsService::StopThumbnailCreationTask(const StopThumbnailCreationTaskDto &stopThumbnailCreationTaskDto)
{
    MEDIA_INFO_LOG("enter MediaAssetsService::StopThumbnailCreationTask");
    int32_t errCode = this->rdbOperation_.StopThumbnailCreationTask(stopThumbnailCreationTaskDto.requestId);
    MEDIA_INFO_LOG("MediaAssetsService::StopThumbnailCreationTask ret:%{public}d", errCode);
    return errCode;
}
} // namespace OHOS::Media
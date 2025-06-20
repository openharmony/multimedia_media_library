/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"){return 0;}
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

#ifndef OHOS_MEDIA_ASSETS_CONTROLLER_SERVICE_H
#define OHOS_MEDIA_ASSETS_CONTROLLER_SERVICE_H

#include "message_parcel.h"
#include "medialibrary_business_code.h"
#include "i_media_controller_service.h"
#include "user_define_ipc.h"
#include "medialibrary_errno.h"

namespace OHOS::Media {
#define EXPORT __attribute__ ((visibility ("default")))
class EXPORT MediaAssetsControllerService : public IPC::IMediaControllerService {
public:
    EXPORT void RemoveFormInfo(MessageParcel &data, MessageParcel &reply);
    EXPORT void RemoveGalleryFormInfo(MessageParcel &data, MessageParcel &reply);
    EXPORT void SaveFormInfo(MessageParcel &data, MessageParcel &reply);
    EXPORT void SaveGalleryFormInfo(MessageParcel &data, MessageParcel &reply);
    EXPORT void CommitEditedAssetOpen(MessageParcel &data, MessageParcel &reply);
    EXPORT void CommitEditedAsset(MessageParcel &data, MessageParcel &reply);
    EXPORT void SysTrashPhotos(MessageParcel &data, MessageParcel &reply);
    EXPORT void TrashPhotos(MessageParcel &data, MessageParcel &reply);
    EXPORT void DeletePhotos(MessageParcel &data, MessageParcel &reply);
    EXPORT void DeletePhotosCompleted(MessageParcel &data, MessageParcel &reply);
    EXPORT void AssetChangeSetFavorite(MessageParcel &data, MessageParcel &reply);
    EXPORT void AssetChangeSetHidden(MessageParcel &data, MessageParcel &reply);
    EXPORT void AssetChangeSetUserComment(MessageParcel &data, MessageParcel &reply);
    EXPORT void AssetChangeSetLocation(MessageParcel &data, MessageParcel &reply);
    EXPORT void AssetChangeSetTitle(MessageParcel &data, MessageParcel &reply);
    EXPORT void AssetChangeSetEditData(MessageParcel &data, MessageParcel &reply);
    EXPORT void AssetChangeSubmitCache(MessageParcel &data, MessageParcel &reply);
    EXPORT void AssetChangeCreateAsset(MessageParcel &data, MessageParcel &reply);
    EXPORT void AssetChangeAddImage(MessageParcel &data, MessageParcel &reply);
    EXPORT void SetCameraShotKey(MessageParcel &data, MessageParcel &reply);
    EXPORT void SaveCameraPhoto(MessageParcel &data, MessageParcel &reply);
    EXPORT void DiscardCameraPhoto(MessageParcel &data, MessageParcel &reply);
    EXPORT void SetEffectMode(MessageParcel &data, MessageParcel &reply);
    EXPORT void SetOrientation(MessageParcel &data, MessageParcel &reply);
    EXPORT void SetVideoEnhancementAttr(MessageParcel &data, MessageParcel &reply);
    EXPORT void SetSupportedWatermarkType(MessageParcel &data, MessageParcel &reply);
    EXPORT void GetAssets(MessageParcel &data, MessageParcel &reply, OHOS::Media::IPC::IPCContext &context);
    EXPORT void GetBurstAssets(MessageParcel &data, MessageParcel &reply, OHOS::Media::IPC::IPCContext &context);
    EXPORT void GetAllDuplicateAssets(MessageParcel &data, MessageParcel &reply);
    EXPORT void GetDuplicateAssetsToDelete(MessageParcel &data, MessageParcel &reply);
    EXPORT void GetIndexConstructProgress(MessageParcel &data, MessageParcel &reply);
    EXPORT void PublicCreateAsset(MessageParcel &data, MessageParcel &reply);
    EXPORT void SystemCreateAsset(MessageParcel &data, MessageParcel &reply);
    EXPORT void PublicCreateAssetForApp(MessageParcel &data, MessageParcel &reply);
    EXPORT void SystemCreateAssetForApp(MessageParcel &data, MessageParcel &reply);
    EXPORT void CreateAssetForAppWithAlbum(MessageParcel &data, MessageParcel &reply);
    EXPORT void SetAssetTitle(MessageParcel &data, MessageParcel &reply);
    EXPORT void SetAssetPending(MessageParcel &data, MessageParcel &reply);
    EXPORT void SetAssetsFavorite(MessageParcel &data, MessageParcel &reply);
    EXPORT void SetAssetsHiddenStatus(MessageParcel &data, MessageParcel &reply);
    EXPORT void SetAssetsRecentShowStatus(MessageParcel &data, MessageParcel &reply);
    EXPORT void SetAssetsUserComment(MessageParcel &data, MessageParcel &reply);
    EXPORT void AddAssetVisitCount(MessageParcel &data, MessageParcel &reply);
    EXPORT void GetAssetAnalysisData(MessageParcel &data, MessageParcel &reply);
    EXPORT void CloneAsset(MessageParcel &data, MessageParcel &reply);
    EXPORT void RevertToOriginal(MessageParcel &data, MessageParcel &reply);
    EXPORT void UpdateGalleryFormInfo(MessageParcel &data, MessageParcel &reply);
    EXPORT void SubmitCloudEnhancementTasks(MessageParcel &data, MessageParcel &reply);
    EXPORT void PrioritizeCloudEnhancementTask(MessageParcel &data, MessageParcel &reply);
    EXPORT void CancelCloudEnhancementTasks(MessageParcel &data, MessageParcel &reply);
    EXPORT void CancelAllCloudEnhancementTasks(MessageParcel &data, MessageParcel &reply);
    EXPORT void StartDownloadCloudMedia(MessageParcel &data, MessageParcel &reply);
    EXPORT void PauseDownloadCloudMedia(MessageParcel &data, MessageParcel &reply);
    EXPORT void CancelDownloadCloudMedia(MessageParcel &data, MessageParcel &reply);
    EXPORT void RetainCloudMediaAsset(MessageParcel &data, MessageParcel &reply);
    EXPORT void GetCloudMediaAssetStatus(MessageParcel &data, MessageParcel &reply);
    EXPORT void GetEditData(MessageParcel &data, MessageParcel &reply);
    EXPORT void RequestEditData(MessageParcel &data, MessageParcel &reply);
    EXPORT void IsEdited(MessageParcel &data, MessageParcel &reply);
    EXPORT void StartAssetAnalysis(MessageParcel &data, MessageParcel &reply);
    EXPORT void GetAlbumsByAlbumIds(MessageParcel &data, MessageParcel &reply);
    EXPORT void GrantPhotoUriPermission(MessageParcel &data, MessageParcel &reply);
    EXPORT void GrantPhotoUrisPermission(MessageParcel &data, MessageParcel &reply);
    EXPORT void GrantPhotoUriPermissionInner(MessageParcel &data, MessageParcel &reply);
    EXPORT void CancelPhotoUriPermission(MessageParcel &data, MessageParcel &reply);
    EXPORT void CancelPhotoUriPermissionInner(MessageParcel &data, MessageParcel &reply);
    EXPORT void StartThumbnailCreationTask(MessageParcel &data, MessageParcel &reply);
    EXPORT void StopThumbnailCreationTask(MessageParcel &data, MessageParcel &reply);
    EXPORT void RequestContent(MessageParcel &data, MessageParcel &reply);
    EXPORT void GetCloudEnhancementPair(MessageParcel &data, MessageParcel &reply);
    EXPORT void QueryCloudEnhancementTaskState(MessageParcel &data, MessageParcel &reply);
    EXPORT void SyncCloudEnhancementTaskStatus(MessageParcel &data, MessageParcel &reply);
    EXPORT void QueryPhotoStatus(MessageParcel &data, MessageParcel &reply);
    EXPORT void LogMovingPhoto(MessageParcel &data, MessageParcel &reply);
    EXPORT void ConvertFormat(MessageParcel &data, MessageParcel &reply);
    EXPORT void GetResultSetFromDb(MessageParcel &data, MessageParcel &reply);
    EXPORT void GetResultSetFromPhotosExtend(MessageParcel &data, MessageParcel &reply);
    EXPORT void GetMovingPhotoDateModified(MessageParcel &data, MessageParcel &reply);
    EXPORT void GetFilePathFromUri(MessageParcel &data, MessageParcel &reply);
    EXPORT void GetUriFromFilePath(MessageParcel &data, MessageParcel &reply);
    EXPORT void CloseAsset(MessageParcel &data, MessageParcel &reply);
    EXPORT void CheckUriPermissionInner(MessageParcel &data, MessageParcel &reply);
    EXPORT void GetUrisByOldUrisInner(MessageParcel &data, MessageParcel &reply);
    EXPORT void Restore(MessageParcel &data, MessageParcel &reply);
    EXPORT void StopRestore(MessageParcel &data, MessageParcel &reply);
public:
    virtual ~MediaAssetsControllerService() = default;
    bool Accept(uint32_t code) override;
    void OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, OHOS::Media::IPC::IPCContext &context) override;
    int32_t GetPermissionPolicy(
        uint32_t code, std::vector<std::vector<PermissionType>> &permissionPolicy, bool &isBypass) override;
};
} // namespace OHOS::Media
#endif  // OHOS_MEDIA_ASSETS_CONTROLLER_SERVICE_H
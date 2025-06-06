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

#define MLOG_TAG "MediaAssetsControllerService"

#include "media_assets_controller_service.h"
#include "media_assets_service.h"
#include "media_log.h"
#include "create_asset_vo.h"
#include "form_info_vo.h"
#include "form_info_dto.h"
#include "modify_assets_vo.h"
#include "parameter_utils.h"
#include "commit_edited_asset_vo.h"
#include "delete_photos_completed_vo.h"
#include "asset_change_vo.h"
#include "delete_photos_vo.h"
#include "trash_photos_vo.h"
#include "clone_asset_vo.h"
#include "clone_asset_dto.h"
#include "revert_to_original_vo.h"
#include "revert_to_original_dto.h"
#include "media_file_utils.h"
#include "cloud_enhancement_vo.h"
#include "cloud_enhancement_dto.h"

#include "start_download_cloud_media_vo.h"
#include "retain_cloud_media_asset_vo.h"
#include "cloud_media_asset_manager.h"
#include "grant_photo_uri_permission_vo.h"
#include "grant_photo_uris_permission_vo.h"
#include "cancel_photo_uri_permission_vo.h"
#include "start_thumbnail_creation_task_vo.h"
#include "stop_thumbnail_creation_task_vo.h"
#include "thumbnail_service.h"

namespace OHOS::Media {
using namespace std;
using RequestHandle = void (MediaAssetsControllerService::*)(MessageParcel &, MessageParcel &);

const std::map<uint32_t, RequestHandle> HANDLERS = {
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::REMOVE_FORM_INFO),
        &MediaAssetsControllerService::RemoveFormInfo
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::REMOVE_GALLERY_FORM_INFO),
        &MediaAssetsControllerService::RemoveGalleryFormInfo
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::SAVE_FORM_INFO),
        &MediaAssetsControllerService::SaveFormInfo
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::SAVE_GALLERY_FORM_INFO),
        &MediaAssetsControllerService::SaveGalleryFormInfo
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::COMMIT_EDITED_ASSET),
        &MediaAssetsControllerService::CommitEditedAsset
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_SYS_TRASH_PHOTOS),
        &MediaAssetsControllerService::SysTrashPhotos
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_TRASH_PHOTOS),
        &MediaAssetsControllerService::TrashPhotos
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_DELETE_PHOTOS),
        &MediaAssetsControllerService::DeletePhotos
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::DELETE_PHOTOS_COMPLETED),
        &MediaAssetsControllerService::DeletePhotosCompleted
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::ASSET_CHANGE_SET_FAVORITE),
        &MediaAssetsControllerService::AssetChangeSetFavorite
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::ASSET_CHANGE_SET_HIDDEN),
        &MediaAssetsControllerService::AssetChangeSetHidden
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::ASSET_CHANGE_SET_USER_COMMENT),
        &MediaAssetsControllerService::AssetChangeSetUserComment
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::ASSET_CHANGE_SET_LOCATION),
        &MediaAssetsControllerService::AssetChangeSetLocation
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::ASSET_CHANGE_SET_TITLE),
        &MediaAssetsControllerService::AssetChangeSetTitle
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::ASSET_CHANGE_SET_EDIT_DATA),
        &MediaAssetsControllerService::AssetChangeSetEditData
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::ASSET_CHANGE_SUBMIT_CACHE),
        &MediaAssetsControllerService::AssetChangeSubmitCache
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::ASSET_CHANGE_CREATE_ASSET),
        &MediaAssetsControllerService::AssetChangeCreateAsset
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::ASSET_CHANGE_ADD_IMAGE),
        &MediaAssetsControllerService::AssetChangeAddImage
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::SET_CAMERA_SHOT_KEY),
        &MediaAssetsControllerService::SetCameraShotKey
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::SAVE_CAMERA_PHOTO),
        &MediaAssetsControllerService::SaveCameraPhoto
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::DISCARD_CAMERA_PHOTO),
        &MediaAssetsControllerService::DiscardCameraPhoto
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::SET_EFFECT_MODE),
        &MediaAssetsControllerService::SetEffectMode
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::SET_ORIENTATION),
        &MediaAssetsControllerService::SetOrientation
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::SET_VIDEO_ENHANCEMENT_ATTR),
        &MediaAssetsControllerService::SetVideoEnhancementAttr
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::SET_SUPPORTED_WATERMARK_TYPE),
        &MediaAssetsControllerService::SetSupportedWatermarkType
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_PUBLIC_CREATE_ASSET),
        &MediaAssetsControllerService::PublicCreateAsset
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_SYSTEM_CREATE_ASSET),
        &MediaAssetsControllerService::SystemCreateAsset
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_PUBLIC_CREATE_ASSET_FOR_APP),
        &MediaAssetsControllerService::PublicCreateAssetForApp
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_SYSTEM_CREATE_ASSET_FOR_APP),
        &MediaAssetsControllerService::SystemCreateAssetForApp
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_SYSTEM_CREATE_ASSET_FOR_APP_WITH_MODE),
        &MediaAssetsControllerService::SystemCreateAssetForApp
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_SYSTEM_CREATE_ASSET_FOR_APP_WITH_ALBUM),
        &MediaAssetsControllerService::CreateAssetForAppWithAlbum
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_PUBLIC_SET_TITLE),
        &MediaAssetsControllerService::SetAssetTitle
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_SYSTEM_SET_PENDING),
        &MediaAssetsControllerService::SetAssetPending
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_SYSTEM_SET_FAVORITE),
        &MediaAssetsControllerService::SetAssetsFavorite
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_SYSTEM_SET_USER_COMMENT),
        &MediaAssetsControllerService::SetAssetsUserComment
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_SYSTEM_BATCH_SET_HIDDEN),
        &MediaAssetsControllerService::SetAssetsHiddenStatus
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_SYSTEM_BATCH_SET_FAVORITE),
        &MediaAssetsControllerService::SetAssetsFavorite
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_SYSTEM_BATCH_SET_RECENT_SHOW),
        &MediaAssetsControllerService::SetAssetsRecentShowStatus
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_SYSTEM_BATCH_SET_USER_COMMENT),
        &MediaAssetsControllerService::SetAssetsUserComment
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::CLONE_ASSET),
        &MediaAssetsControllerService::CloneAsset
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::REVERT_TO_ORIGINAL),
        &MediaAssetsControllerService::RevertToOriginal
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::UPDATE_GALLERY_FORM_INFO),
        &MediaAssetsControllerService::UpdateGalleryFormInfo
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::SUBMIT_CLOUD_ENHANCEMENT_TASKS),
        &MediaAssetsControllerService::SubmitCloudEnhancementTasks
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PRIORITIZE_CLOUD_ENHANCEMENT_TASK),
        &MediaAssetsControllerService::PrioritizeCloudEnhancementTask
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::CANCEL_CLOUD_ENHANCEMENT_TASKS),
        &MediaAssetsControllerService::CancelCloudEnhancementTasks
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::CANCEL_ALL_CLOUD_ENHANCEMENT_TASKS),
        &MediaAssetsControllerService::CancelAllCloudEnhancementTasks
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::START_DOWNLOAD_CLOUDMEDIA),
        &MediaAssetsControllerService::StartDownloadCloudMedia
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAUSE_DOWNLOAD_CLOUDMEDIA),
        &MediaAssetsControllerService::PauseDownloadCloudMedia
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::CANCEL_DOWNLOAD_CLOUDMEDIA),
        &MediaAssetsControllerService::CancelDownloadCloudMedia
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::RETAIN_CLOUDMEDIA_ASSET),
        &MediaAssetsControllerService::RetainCloudMediaAsset
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_GRANT_PHOTO_URI_PERMISSION),
        &MediaAssetsControllerService::GrantPhotoUriPermission
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_GRANT_PHOTO_URIS_PERMISSION),
        &MediaAssetsControllerService::GrantPhotoUrisPermission
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_CANCEL_PHOTO_URI_PERMISSION),
        &MediaAssetsControllerService::CancelPhotoUriPermission
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_START_THUMBNAIL_CREATION_TASK),
        &MediaAssetsControllerService::StartThumbnailCreationTask
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_STOP_THUMBNAIL_CREATION_TASK),
        &MediaAssetsControllerService::StopThumbnailCreationTask
    },
};

bool MediaAssetsControllerService::Accept(uint32_t code)
{
    return HANDLERS.find(code) != HANDLERS.end();
}

void MediaAssetsControllerService::OnRemoteRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, OHOS::Media::IPC::IPCContext &context)
{
    auto it = HANDLERS.find(code);
    if (it == HANDLERS.end()) {
        return IPC::UserDefineIPC().WriteResponseBody(reply, E_IPC_SEVICE_NOT_FOUND);
    }
    return (this->*(it->second))(data, reply);
}

void MediaAssetsControllerService::RemoveFormInfo(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter RemoveFormInfo");
    FormInfoReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("RemoveFormInfo Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    ret = ParameterUtils::CheckFormIds(reqBody.formIds);
    if (ret == E_OK) {
        ret = MediaAssetsService::GetInstance().RemoveFormInfo(reqBody.formIds.front());
    }
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::RemoveGalleryFormInfo(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter RemoveGalleryFormInfo");
    FormInfoReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("RemoveFormInfo Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    ret = ParameterUtils::CheckFormIds(reqBody.formIds);
    if (ret == E_OK) {
        ret = MediaAssetsService::GetInstance().RemoveGalleryFormInfo(reqBody.formIds.front());
    }
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::SaveFormInfo(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter SaveFormInfo");
    FormInfoReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("SaveFormInfo Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    ret = ParameterUtils::CheckFormIds(reqBody.formIds);
    FormInfoDto formInfoDto;
    formInfoDto.formIds = reqBody.formIds;
    formInfoDto.fileUris = reqBody.fileUris;
    if (formInfoDto.formIds.empty() || formInfoDto.fileUris.empty()) {
        MEDIA_ERR_LOG("formIds or fileUris is empty");
        ret = E_GET_PRAMS_FAIL;
    }
    if (ret == E_OK) {
        ret = MediaAssetsService::GetInstance().SaveFormInfo(formInfoDto);
    }
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::SaveGalleryFormInfo(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter SaveGalleryFormInfo");
    FormInfoReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("SaveGalleryFormInfo Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    ret = ParameterUtils::CheckFormIds(reqBody.formIds);
    FormInfoDto formInfoDto;
    formInfoDto.formIds = reqBody.formIds;
    formInfoDto.fileUris = reqBody.fileUris;
    bool cond = (formInfoDto.formIds.size() != formInfoDto.fileUris.size()) || formInfoDto.formIds.empty()
        || formInfoDto.fileUris.empty();
    ret = cond ? E_GET_PRAMS_FAIL : ret;
    CHECK_AND_PRINT_LOG(!cond, "formIds or fileUris is empty or count not equal");
    if (ret == E_OK) {
        ret = MediaAssetsService::GetInstance().SaveGalleryFormInfo(formInfoDto);
    }
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::CommitEditedAsset(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter CommitEditedAsset");
    CommitEditedAssetReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("CommitEditedAsset Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }

    bool cond = ParameterUtils::CheckEditDataLength(reqBody.editData) && reqBody.fileId > 0;
    if (!cond) {
        MEDIA_ERR_LOG("params not valid");
        ret = E_INVALID_VALUES;
    }

    CommitEditedAssetDto commitEditedAssetDto;
    commitEditedAssetDto.editData = reqBody.editData;
    commitEditedAssetDto.fileId = reqBody.fileId;

    if (ret == E_OK) {
        ret = MediaAssetsService::GetInstance().CommitEditedAsset(commitEditedAssetDto);
    }
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::SysTrashPhotos(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter SysTrashPhotos");
    TrashPhotosReqBody reqBody;

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("SysTrashPhotos Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    if (reqBody.uris.empty()) {
        MEDIA_ERR_LOG("uris is empty");
        IPC::UserDefineIPC().WriteResponseBody(reply, -EINVAL);
        return;
    }
    ret = MediaAssetsService::GetInstance().TrashPhotos(reqBody.uris);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::TrashPhotos(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter TrashPhotos");
    TrashPhotosReqBody reqBody;

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("TrashPhotos Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    ret = ParameterUtils::CheckTrashPhotos(reqBody.uris);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        MEDIA_ERR_LOG("uris is invalid");
        return;
    }

    ret = MediaAssetsService::GetInstance().TrashPhotos(reqBody.uris);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::DeletePhotos(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter DeletePhotos");
    DeletePhotosReqBody reqBody;

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("DeletePhotos Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    if (reqBody.uris.empty()) {
        MEDIA_ERR_LOG("uris is empty");
        IPC::UserDefineIPC().WriteResponseBody(reply, -EINVAL);
        return;
    }
    ret = MediaAssetsService::GetInstance().DeletePhotos(reqBody.uris);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::DeletePhotosCompleted(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter DeletePhotosCompleted");
    DeletePhotosCompletedReqBody reqBody;

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("DeletePhotosCompleted Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    ret = ParameterUtils::CheckDeletePhotosCompleted(reqBody.fileIds);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        MEDIA_ERR_LOG("fileIds is invalid");
        return;
    }

    ret = MediaAssetsService::GetInstance().DeletePhotosCompleted(reqBody.fileIds);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::AssetChangeSetFavorite(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter AssetChangeSetFavorite");
    AssetChangeReqBody reqBody;

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("AssetChangeSetFavorite Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    if (reqBody.fileId <= 0) {
        IPC::UserDefineIPC().WriteResponseBody(reply, -EINVAL);
        MEDIA_ERR_LOG("fileId is invalid");
        return;
    }

    ret = MediaAssetsService::GetInstance().AssetChangeSetFavorite(reqBody.fileId, reqBody.favorite);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::AssetChangeSetHidden(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter AssetChangeSetHidden");
    AssetChangeReqBody reqBody;

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("AssetChangeSetHidden Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    if (!ParameterUtils::CheckOpenUriLength(reqBody.uri)) {
        IPC::UserDefineIPC().WriteResponseBody(reply, -EINVAL);
        MEDIA_ERR_LOG("uri is invalid");
        return;
    }

    ret = MediaAssetsService::GetInstance().AssetChangeSetHidden(reqBody.uri, reqBody.hidden);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::AssetChangeSetUserComment(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter AssetChangeSetUserComment");
    AssetChangeReqBody reqBody;

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("AssetChangeSetUserComment Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    ret = ParameterUtils::CheckUserComment(reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, -EINVAL);
        MEDIA_ERR_LOG("params is invalid");
        return;
    }

    ret = MediaAssetsService::GetInstance().AssetChangeSetUserComment(reqBody.fileId, reqBody.userComment);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::AssetChangeSetLocation(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter AssetChangeSetLocation");
    AssetChangeReqBody reqBody;

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("AssetChangeSetLocation Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }

    if (reqBody.fileId <= 0) {
        IPC::UserDefineIPC().WriteResponseBody(reply, -EINVAL);
        MEDIA_ERR_LOG("params is invalid");
        return;
    }

    auto dto = SetLocationDto::Create(reqBody);
    ret = MediaAssetsService::GetInstance().AssetChangeSetLocation(dto);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::AssetChangeSetTitle(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter AssetChangeSetTitle");
    AssetChangeReqBody reqBody;

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("AssetChangeSetTitle Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }

    if (reqBody.fileId <= 0) {
        IPC::UserDefineIPC().WriteResponseBody(reply, -EINVAL);
        MEDIA_ERR_LOG("params is invalid");
        return;
    }

    ret = MediaAssetsService::GetInstance().AssetChangeSetTitle(reqBody.fileId, reqBody.title);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::AssetChangeSetEditData(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter AssetChangeSetEditData");
    AssetChangeReqBody reqBody;

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("AssetChangeSetEditData Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }

    if (reqBody.values.IsEmpty()) {
        IPC::UserDefineIPC().WriteResponseBody(reply, -EINVAL);
        MEDIA_ERR_LOG("params is invalid");
        return;
    }

    ret = MediaAssetsService::GetInstance().AssetChangeSetEditData(reqBody.values);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::AssetChangeSubmitCache(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter AssetChangeSubmitCache");
    SubmitCacheReqBody reqBody;

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("AssetChangeSubmitCache Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }

    if (reqBody.values.IsEmpty()) {
        IPC::UserDefineIPC().WriteResponseBody(reply, -EINVAL);
        MEDIA_ERR_LOG("params is invalid");
        return;
    }
    auto dto = SubmitCacheDto::Create(reqBody);
    ret = MediaAssetsService::GetInstance().AssetChangeSubmitCache(dto);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("AssetChangeSubmitCache Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    auto rspBody = dto.CreateRspBody();
    IPC::UserDefineIPC().WriteResponseBody(reply, rspBody);
}

void MediaAssetsControllerService::AssetChangeCreateAsset(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter AssetChangeCreateAsset");
    AssetChangeReqBody reqBody;

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("AssetChangeCreateAsset Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }

    if (reqBody.values.IsEmpty()) {
        IPC::UserDefineIPC().WriteResponseBody(reply, -EINVAL);
        MEDIA_ERR_LOG("params is invalid");
        return;
    }
    auto dto = AssetChangeCreateAssetDto::Create(reqBody);
    ret = MediaAssetsService::GetInstance().AssetChangeCreateAsset(dto);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("AssetChangeCreateAsset Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    auto rspBody = dto.CreateRspBody();
    IPC::UserDefineIPC().WriteResponseBody(reply, rspBody);
}

void MediaAssetsControllerService::AssetChangeAddImage(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter AssetChangeAddImage");
    AddImageReqBody reqBody;

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("AssetChangeAddImage Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }

    if (reqBody.fileId <= 0) {
        IPC::UserDefineIPC().WriteResponseBody(reply, -EINVAL);
        MEDIA_ERR_LOG("params is invalid");
        return;
    }
    auto dto = AddImageDto::Create(reqBody);
    ret = MediaAssetsService::GetInstance().AssetChangeAddImage(dto);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::SetCameraShotKey(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter SetCameraShotKey");
    AssetChangeReqBody reqBody;

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("SetCameraShotKey Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }

    ret = ParameterUtils::CheckCameraShotKey(reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        MEDIA_ERR_LOG("params is invalid");
        return;
    }
    ret = MediaAssetsService::GetInstance().SetCameraShotKey(reqBody.fileId, reqBody.cameraShotKey);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::SaveCameraPhoto(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter SaveCameraPhoto");
    SaveCameraPhotoReqBody reqBody;

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("SaveCameraPhoto Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }

    if (reqBody.fileId <= 0) {
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        MEDIA_ERR_LOG("params is invalid");
        return;
    }
    auto dto = SaveCameraPhotoDto::Create(reqBody);
    ret = MediaAssetsService::GetInstance().SaveCameraPhoto(dto);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::DiscardCameraPhoto(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter DiscardCameraPhoto");
    AssetChangeReqBody reqBody;

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("DiscardCameraPhoto Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }

    if (reqBody.fileId <= 0) {
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        MEDIA_ERR_LOG("params is invalid");
        return;
    }
    ret = MediaAssetsService::GetInstance().DiscardCameraPhoto(reqBody.fileId);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::SetEffectMode(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter SetEffectMode");
    AssetChangeReqBody reqBody;

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("SetEffectMode Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }

    if (reqBody.fileId <= 0|| !MediaFileUtils::CheckMovingPhotoEffectMode(reqBody.effectMode)) {
        IPC::UserDefineIPC().WriteResponseBody(reply, -EINVAL);
        MEDIA_ERR_LOG("params is invalid");
        return;
    }
    ret = MediaAssetsService::GetInstance().SetEffectMode(reqBody.fileId, reqBody.effectMode);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::SetOrientation(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter SetOrientation");
    AssetChangeReqBody reqBody;

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("SetOrientation Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }

    ret = ParameterUtils::CheckOrientation(reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        MEDIA_ERR_LOG("params is invalid");
        return;
    }
    ret = MediaAssetsService::GetInstance().SetOrientation(reqBody.fileId, reqBody.orientation);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::SetVideoEnhancementAttr(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter SetVideoEnhancementAttr");
    AssetChangeReqBody reqBody;

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("SetVideoEnhancementAttr Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }

    ret = ParameterUtils::CheckVideoEnhancementAttr(reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        MEDIA_ERR_LOG("params is invalid");
        return;
    }
    ret = MediaAssetsService::GetInstance().SetVideoEnhancementAttr(reqBody.fileId, reqBody.photoId, reqBody.path);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::SetSupportedWatermarkType(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter SetSupportedWatermarkType");
    AssetChangeReqBody reqBody;

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("SetSupportedWatermarkType Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }

    ret = ParameterUtils::CheckWatermarkType(reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        MEDIA_ERR_LOG("params is invalid");
        return;
    }
    ret = MediaAssetsService::GetInstance().SetSupportedWatermarkType(reqBody.fileId, reqBody.watermarkType);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::PublicCreateAsset(MessageParcel &data, MessageParcel &reply)
{
    CreateAssetReqBody reqBody;
    CreateAssetRspBody rspBody;
    MEDIA_INFO_LOG("enter PublicCreateAsset");
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, rspBody, ret);
        MEDIA_ERR_LOG("PublicCreateAsset Read Request Error");
        return;
    }

    ret = ParameterUtils::CheckPublicCreateAsset(reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, rspBody, ret);
        MEDIA_ERR_LOG("CheckPublicCreateAsset ret:%{public}d", ret);
        return;
    }

    CreateAssetDto dto;
    reqBody.Convert2Dto(dto);
    ret = MediaAssetsService::GetInstance().CreateAsset(dto);
    if (ret == E_OK) {
        rspBody.InitByDto(dto);
    }
    IPC::UserDefineIPC().WriteResponseBody(reply, rspBody, ret);
}

void MediaAssetsControllerService::SystemCreateAsset(MessageParcel &data, MessageParcel &reply)
{
    CreateAssetReqBody reqBody;
    CreateAssetRspBody rspBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, rspBody, ret);
        MEDIA_ERR_LOG("SystemCreateAsset Read Request Error");
        return;
    }

    ret = ParameterUtils::CheckSystemCreateAsset(reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, rspBody, ret);
        MEDIA_ERR_LOG("CheckSystemCreateAsset ret:%{public}d", ret);
        return;
    }

    CreateAssetDto dto;
    reqBody.Convert2Dto(dto);
    (void)ParameterUtils::GetTitleAndExtension(dto.displayName, dto.title, dto.extension);
    ret = MediaAssetsService::GetInstance().CreateAsset(dto);
    if (ret == E_OK) {
        rspBody.InitByDto(dto);
    }
    IPC::UserDefineIPC().WriteResponseBody(reply, rspBody, ret);
}

void MediaAssetsControllerService::PublicCreateAssetForApp(MessageParcel &data, MessageParcel &reply)
{
    CreateAssetForAppReqBody reqBody;
    CreateAssetForAppRspBody rspBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, rspBody, ret);
        MEDIA_ERR_LOG("CreateAssetForApp Read Request Error");
        return;
    }

    ret = ParameterUtils::CheckPublicCreateAssetForApp(reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, rspBody, ret);
        MEDIA_ERR_LOG("CheckPublicCreateAssetForApp ret:%{public}d", ret);
        return;
    }

    CreateAssetDto dto;
    reqBody.Convert2Dto(dto);
    ret = MediaAssetsService::GetInstance().CreateAssetForApp(dto);
    if (ret == E_OK) {
        rspBody.InitByDto(dto);
    }
    IPC::UserDefineIPC().WriteResponseBody(reply, rspBody, ret);
}

void MediaAssetsControllerService::SystemCreateAssetForApp(MessageParcel &data, MessageParcel &reply)
{
    CreateAssetForAppReqBody reqBody;
    CreateAssetForAppRspBody rspBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, rspBody, ret);
        MEDIA_ERR_LOG("CreateAssetForApp Read Request Error");
        return;
    }

    ret = ParameterUtils::CheckSystemCreateAssetForApp(reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, rspBody, ret);
        MEDIA_ERR_LOG("CheckSystemCreateAssetForApp ret:%{public}d", ret);
        return;
    }

    CreateAssetDto dto;
    reqBody.Convert2Dto(dto);
    ret = MediaAssetsService::GetInstance().CreateAssetForApp(dto);
    if (ret == E_OK) {
        rspBody.InitByDto(dto);
    }
    IPC::UserDefineIPC().WriteResponseBody(reply, rspBody, ret);
}

void MediaAssetsControllerService::CreateAssetForAppWithAlbum(MessageParcel &data, MessageParcel &reply)
{
    CreateAssetForAppReqBody reqBody;
    CreateAssetForAppRspBody rspBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, rspBody, ret);
        MEDIA_ERR_LOG("CreateAssetForAppWithAlbum Read Request Error");
        return;
    }

    ret = ParameterUtils::CheckCreateAssetForAppWithAlbum(reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, rspBody, ret);
        MEDIA_ERR_LOG("CheckCreateAssetForAppWithAlbum ret:%{public}d", ret);
        return;
    }

    CreateAssetDto dto;
    reqBody.Convert2Dto(dto);
    ret = MediaAssetsService::GetInstance().CreateAssetForAppWithAlbum(dto);
    if (ret == E_OK) {
        rspBody.InitByDto(dto);
    }
    IPC::UserDefineIPC().WriteResponseBody(reply, rspBody, ret);
}

void MediaAssetsControllerService::SetAssetTitle(MessageParcel &data, MessageParcel &reply)
{
    ModifyAssetsReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        MEDIA_ERR_LOG("SetAssetTitle Read Request Error");
        return;
    }

    ret = ParameterUtils::CheckSetAssetTitle(reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        MEDIA_ERR_LOG("CheckSetAssetTitle ret:%{public}d", ret);
        return;
    }

    ret = MediaAssetsService::GetInstance().SetAssetTitle(reqBody.fileIds.front(), reqBody.title);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::SetAssetPending(MessageParcel &data, MessageParcel &reply)
{
    ModifyAssetsReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        MEDIA_ERR_LOG("SetAssetPending Read Request Error");
        return;
    }

    ret = ParameterUtils::CheckSetAssetPending(reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        MEDIA_ERR_LOG("CheckSetAssetPending ret:%{public}d", ret);
        return;
    }

    ret = MediaAssetsService::GetInstance().SetAssetPending(reqBody.fileIds.front(), reqBody.pending);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::SetAssetsFavorite(MessageParcel &data, MessageParcel &reply)
{
    ModifyAssetsReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        MEDIA_ERR_LOG("SetAssetsFavorite Read Request Error");
        return;
    }

    ret = ParameterUtils::CheckSetAssetsFavorite(reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        MEDIA_ERR_LOG("CheckSetAssetsFavorite ret:%{public}d", ret);
        return;
    }

    ret = MediaAssetsService::GetInstance().SetAssetsFavorite(reqBody.fileIds, reqBody.favorite);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::SetAssetsHiddenStatus(MessageParcel &data, MessageParcel &reply)
{
    ModifyAssetsReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        MEDIA_ERR_LOG("SetAssetsHiddenStatus Read Request Error");
        return;
    }

    ret = ParameterUtils::CheckSetAssetsHiddenStatus(reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        MEDIA_ERR_LOG("CheckSetAssetsHiddenStatus ret:%{public}d", ret);
        return;
    }

    ret = MediaAssetsService::GetInstance().SetAssetsHiddenStatus(reqBody.fileIds, reqBody.hiddenStatus);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::SetAssetsRecentShowStatus(MessageParcel &data, MessageParcel &reply)
{
    ModifyAssetsReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        MEDIA_ERR_LOG("SetAssetsRecentShowStatus Read Request Error");
        return;
    }

    ret = ParameterUtils::CheckSetAssetsRecentShowStatus(reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        MEDIA_ERR_LOG("CheckSetAssetsRecentShowStatus ret:%{public}d", ret);
        return;
    }

    ret = MediaAssetsService::GetInstance().SetAssetsRecentShowStatus(reqBody.fileIds, reqBody.recentShowStatus);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::SetAssetsUserComment(MessageParcel &data, MessageParcel &reply)
{
    ModifyAssetsReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        MEDIA_ERR_LOG("SetAssetsUserComment Read Request Error");
        return;
    }

    ret = ParameterUtils::CheckSetAssetsUserComment(reqBody);
    if (ret != E_OK) {
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        MEDIA_ERR_LOG("CheckSetAssetsUserComment ret:%{public}d", ret);
        return;
    }

    ret = MediaAssetsService::GetInstance().SetAssetsUserComment(reqBody.fileIds, reqBody.userComment);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::CloneAsset(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter CloneAsset");
    CloneAssetReqBody reqBody;

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("CloneAsset Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    string extension = MediaFileUtils::SplitByChar(reqBody.displayName, '.');
    string displayName = reqBody.title + "." + extension;
    if (MediaFileUtils::CheckDisplayName(displayName, true) != E_OK) {
        MEDIA_ERR_LOG("CloneAsset invalid params");
        IPC::UserDefineIPC().WriteResponseBody(reply, E_INVALID_VALUES);
        return;
    }

    CloneAssetDto cloneAssetDto;
    cloneAssetDto.fileId = reqBody.fileId;
    cloneAssetDto.title = reqBody.title;
    int32_t newAssetId = MediaAssetsService::GetInstance().CloneAsset(cloneAssetDto);
    IPC::UserDefineIPC().WriteResponseBody(reply, newAssetId);
}

void MediaAssetsControllerService::RevertToOriginal(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter RevertToOriginal");
    RevertToOriginalReqBody reqBody;

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("RevertToOriginal Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    RevertToOriginalDto revertToOriginalDto;
    revertToOriginalDto.fileId = reqBody.fileId;
    revertToOriginalDto.fileUri = reqBody.fileUri;

    ret = MediaAssetsService::GetInstance().RevertToOriginal(revertToOriginalDto);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::UpdateGalleryFormInfo(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter UpdateGalleryFormInfo");
    FormInfoReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("UpdateGalleryFormInfo Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    ret = ParameterUtils::CheckFormIds(reqBody.formIds);
    FormInfoDto formInfoDto;
    formInfoDto.formIds = reqBody.formIds;
    formInfoDto.fileUris = reqBody.fileUris;
    bool cond = (formInfoDto.formIds.size() != formInfoDto.fileUris.size()) || formInfoDto.formIds.empty()
        || formInfoDto.fileUris.empty();
    if (cond) {
        MEDIA_ERR_LOG("formIds or fileUris is empty or count not equal");
        ret = E_GET_PRAMS_FAIL;
    }
    if (ret == E_OK) {
        ret = MediaAssetsService::GetInstance().RemoveGalleryFormInfo(reqBody.formIds.front());
        ret = MediaAssetsService::GetInstance().SaveGalleryFormInfo(formInfoDto);
    }
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::SubmitCloudEnhancementTasks(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter SubmitCloudEnhancementTasks");
    CloudEnhancementReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("SubmitCloudEnhancementTasks Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    bool isValid = false;
    for (auto uri : reqBody.fileUris) {
        isValid = ParameterUtils::IsPhotoUri(uri);
    }
    if (!isValid) {
        MEDIA_ERR_LOG("fileUris in params is invalid");
        ret = E_GET_PRAMS_FAIL;
    }
    CloudEnhancementDto dto;
    dto.hasCloudWatermark = reqBody.hasCloudWatermark;
    dto.triggerMode = reqBody.triggerMode;
    dto.fileUris = reqBody.fileUris;
    if (ret == E_OK) {
        ret = MediaAssetsService::GetInstance().SubmitCloudEnhancementTasks(dto);
    }
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::PrioritizeCloudEnhancementTask(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter PrioritizeCloudEnhancementTask");
    CloudEnhancementReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("PrioritizeCloudEnhancementTask Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    bool isValid = false;
    for (auto uri : reqBody.fileUris) {
        isValid = ParameterUtils::IsPhotoUri(uri);
    }
    if (!isValid) {
        MEDIA_ERR_LOG("fileUris in params is invalid");
        ret = E_GET_PRAMS_FAIL;
    }
    CloudEnhancementDto dto;
    dto.fileUris = reqBody.fileUris;
    if (ret == E_OK) {
        ret = MediaAssetsService::GetInstance().PrioritizeCloudEnhancementTask(dto);
    }
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::CancelCloudEnhancementTasks(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter CancelCloudEnhancementTasks");
    CloudEnhancementReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("CancelCloudEnhancementTasks Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    bool isValid = false;
    for (auto uri : reqBody.fileUris) {
        isValid = ParameterUtils::IsPhotoUri(uri);
    }
    if (!isValid) {
        MEDIA_ERR_LOG("fileUris in params is invalid");
        ret = E_GET_PRAMS_FAIL;
    }
    CloudEnhancementDto dto;
    dto.fileUris = reqBody.fileUris;
    if (ret == E_OK) {
        ret = MediaAssetsService::GetInstance().SubmitCloudEnhancementTasks(dto);
    }
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::CancelAllCloudEnhancementTasks(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter CancelAllCloudEnhancementTasks");
    CloudEnhancementReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("CancelAllCloudEnhancementTasks Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    if (ret == E_OK) {
        ret = MediaAssetsService::GetInstance().CancelAllCloudEnhancementTasks();
    }
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::StartDownloadCloudMedia(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter StartDownloadCloudMedia");
    StartDownloadCloudMediaReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("StartDownloadCloudMedia Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    CloudMediaDownloadType downloadType = static_cast<CloudMediaDownloadType>(reqBody.cloudMediaType);

    if (downloadType != CloudMediaDownloadType::DOWNLOAD_FORCE &&
            downloadType != CloudMediaDownloadType::DOWNLOAD_GENTLE) {
        ret = E_INVALID_VALUES;
        MEDIA_ERR_LOG("StartDownloadCloudMedia error, err param");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    CloudMediaAssetManager &instance = CloudMediaAssetManager::GetInstance();
    ret = instance.StartDownloadCloudAsset(downloadType);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::PauseDownloadCloudMedia(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter PauseDownloadCloudMedia");
    CloudMediaAssetManager &instance =  CloudMediaAssetManager::GetInstance();
    int32_t ret = instance.PauseDownloadCloudAsset(CloudMediaTaskPauseCause::USER_PAUSED);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::CancelDownloadCloudMedia(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter CancelDownloadCloudMedia");
    CloudMediaAssetManager &instance =  CloudMediaAssetManager::GetInstance();
    int32_t ret = instance.CancelDownloadCloudAsset();
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
}

void MediaAssetsControllerService::RetainCloudMediaAsset(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter RetainCloudMediaAsset");
    RetainCloudMediaAssetReqBody reqBody;
    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("StartDownloadCloudMedia Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    if (reqBody.cloudMediaRetainType == static_cast<int32_t>(CloudMediaRetainType::RETAIN_FORCE)) {
        CloudMediaAssetManager &instance = CloudMediaAssetManager::GetInstance();
        ret = instance.ForceRetainDownloadCloudMedia();
    } else {
        ret = E_INVALID_VALUES;
        MEDIA_ERR_LOG("RetainCloudMediaAsset error, err type: %{public}d", reqBody.cloudMediaRetainType);
    }
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    return;
}
void MediaAssetsControllerService::GrantPhotoUriPermission(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter GrantPhotoUriPermission");
    GrantUriPermissionReqBody reqBody;

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("GrantPhotoUriPermission Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    GrantUriPermissionDto grantUriPermDto;
    grantUriPermDto.tokenId = reqBody.tokenId;
    grantUriPermDto.srcTokenId = reqBody.srcTokenId;
    grantUriPermDto.fileId = reqBody.fileId;
    grantUriPermDto.permissionType = reqBody.permissionType;
    grantUriPermDto.hideSensitiveType = reqBody.hideSensitiveType;
    grantUriPermDto.uriType = reqBody.uriType;

    ret = MediaAssetsService::GetInstance().GrantPhotoUriPermission(grantUriPermDto);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    return;
}

void MediaAssetsControllerService::GrantPhotoUrisPermission(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter GrantPhotoUrisPermission");
    GrantUrisPermissionReqBody reqBody;

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("GrantPhotoUrisPermission Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    GrantUrisPermissionDto grantUrisPermDto;
    grantUrisPermDto.tokenId = reqBody.tokenId;
    grantUrisPermDto.srcTokenId = reqBody.srcTokenId;
    grantUrisPermDto.fileIds.assign(reqBody.fileIds.begin(), reqBody.fileIds.end());
    grantUrisPermDto.permissionType = reqBody.permissionType;
    grantUrisPermDto.hideSensitiveType = reqBody.hideSensitiveType;
    grantUrisPermDto.uriType = reqBody.uriType;

    ret = MediaAssetsService::GetInstance().GrantPhotoUrisPermission(grantUrisPermDto);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    return;
}

void MediaAssetsControllerService::CancelPhotoUriPermission(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter GrantPhotoUriPermission");
    CancelUriPermissionReqBody reqBody;

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("CancelPhotoUriPermission Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    CancelUriPermissionDto cancelUriPermDto;
    cancelUriPermDto.tokenId = reqBody.tokenId;
    cancelUriPermDto.srcTokenId = reqBody.srcTokenId;
    cancelUriPermDto.fileId = reqBody.fileId;
    cancelUriPermDto.permissionType = reqBody.permissionType;

    cancelUriPermDto.uriType = reqBody.uriType;

    ret = MediaAssetsService::GetInstance().CancelPhotoUriPermission(cancelUriPermDto);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    return;
}

void MediaAssetsControllerService::StartThumbnailCreationTask(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter StartThumbnailCreationTask");
    StartThumbnailCreationTaskReqBody reqBody;

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("StartThumbnailCreationTask Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    StartThumbnailCreationTaskDto startCreationTaskDto;
    startCreationTaskDto.predicates = reqBody.predicates;
    startCreationTaskDto.requestId = reqBody.requestId;
    ret = MediaAssetsService::GetInstance().StartThumbnailCreationTask(startCreationTaskDto);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    return;
}

void MediaAssetsControllerService::StopThumbnailCreationTask(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_INFO_LOG("enter StopThumbnailCreationTask");
    StopThumbnailCreationTaskReqBody reqBody;

    int32_t ret = IPC::UserDefineIPC().ReadRequestBody(data, reqBody);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("StopThumbnailCreationTask Read Request Error");
        IPC::UserDefineIPC().WriteResponseBody(reply, ret);
        return;
    }
    StopThumbnailCreationTaskDto stopCreationTaskDto;
    stopCreationTaskDto.requestId = reqBody.requestId;
    ret = MediaAssetsService::GetInstance().StopThumbnailCreationTask(stopCreationTaskDto);
    IPC::UserDefineIPC().WriteResponseBody(reply, ret);
    return;
}
} // namespace OHOS::Media
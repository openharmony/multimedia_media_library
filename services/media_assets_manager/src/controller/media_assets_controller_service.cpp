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
#include "parameter_utils.h"
#include "commit_edited_asset_vo.h"
#include "delete_photos_completed_vo.h"
#include "delete_photos_vo.h"
#include "trash_photos_vo.h"
#include "clone_asset_vo.h"
#include "clone_asset_dto.h"
#include "revert_to_original_vo.h"
#include "revert_to_original_dto.h"
#include "media_file_utils.h"


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
        static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_TRASH_PHOTO),
        &MediaAssetsControllerService::TrashPhotos
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::DELETE_PHOTOS_COMPLETED),
        &MediaAssetsControllerService::DeletePhotosCompleted
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
        static_cast<uint32_t>(MediaLibraryBusinessCode::CLONE_ASSET),
        &MediaAssetsControllerService::CloneAsset
    },
    {
        static_cast<uint32_t>(MediaLibraryBusinessCode::REVERT_TO_ORIGINAL),
        &MediaAssetsControllerService::RevertToOriginal
    },
};

bool MediaAssetsControllerService::Accept(uint32_t code)
{
    return HANDLERS.find(code) != HANDLERS.end();
}

void MediaAssetsControllerService::OnRemoteRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
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
        MEDIA_ERR_LOG("reqBody:%{public}s", reqBody.ToString().c_str());
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
        MEDIA_ERR_LOG("reqBody:%{public}s", reqBody.ToString().c_str());
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
        MEDIA_ERR_LOG("reqBody:%{public}s", reqBody.ToString().c_str());
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
        MEDIA_ERR_LOG("reqBody:%{public}s", reqBody.ToString().c_str());
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
        MEDIA_ERR_LOG("reqBody:%{public}s", reqBody.ToString().c_str());
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
} // namespace OHOS::Media
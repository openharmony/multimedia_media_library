/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "media_asset_change_request_capi.h"

#include "media_log.h"
#include "media_asset_change_request_impl.h"
#include "media_asset_impl.h"
#include "userfile_manager_types.h"

MediaLibrary_ErrorCode OH_MediaAssetChangeRequest_SaveCameraPhoto(OH_MediaAssetChangeRequest* changeRequest,
    MediaLibrary_ImageFileType imageFileType)
{
    CHECK_AND_RETURN_RET_LOG(changeRequest != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "changeRequest is nullptr!");

    return changeRequest->SaveCameraPhoto(imageFileType);
}

MediaLibrary_ErrorCode OH_MediaAssetChangeRequest_DiscardCameraPhoto(OH_MediaAssetChangeRequest* changeRequest)
{
    CHECK_AND_RETURN_RET_LOG(changeRequest != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "changeRequest is nullptr!");

    return changeRequest->DiscardCameraPhoto();
}

OH_MediaAssetChangeRequest* OH_MediaAssetChangeRequest_Create(OH_MediaAsset* mediaAsset)
{
    CHECK_AND_RETURN_RET_LOG(mediaAsset != nullptr, nullptr, "mediaAsset is nullptr!");
    auto fileAssetPtr = mediaAsset->GetFileAssetInstance();
    CHECK_AND_RETURN_RET_LOG(fileAssetPtr != nullptr, nullptr, "fileAssetPtr is nullptr!");

    OH_MediaAssetChangeRequest* changeRequest = nullptr;
    if (fileAssetPtr->GetMediaType() == OHOS::Media::MEDIA_TYPE_IMAGE ||
        fileAssetPtr->GetMediaType() == OHOS::Media::MEDIA_TYPE_VIDEO) {
        changeRequest = new OH_MediaAssetChangeRequest(mediaAsset);
        CHECK_AND_RETURN_RET_LOG(changeRequest != nullptr, nullptr, "create OH_MediaAssetChangeRequest failed!");
    }
    return changeRequest;
}

MediaLibrary_ErrorCode OH_MediaAssetChangeRequest_AddResourceWithBuffer(OH_MediaAssetChangeRequest* changeRequest,
    MediaLibrary_ResourceType resourceType, uint8_t* buffer, uint32_t length)
{
    CHECK_AND_RETURN_RET_LOG(changeRequest != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "changeRequest is nullptr!");
    CHECK_AND_RETURN_RET_LOG(buffer != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "buffer is null");
    CHECK_AND_RETURN_RET_LOG(length > 0, MEDIA_LIBRARY_PARAMETER_ERROR, "length is zero");

    return changeRequest->AddResourceWithBuffer(resourceType, buffer, length);
}

MediaLibrary_ErrorCode OH_MediaAssetChangeRequest_Release(OH_MediaAssetChangeRequest* changeRequest)
{
    CHECK_AND_RETURN_RET_LOG(changeRequest != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "changeRequest is nullptr!");

    delete changeRequest;
    changeRequest = nullptr;
    return MEDIA_LIBRARY_OK;
}
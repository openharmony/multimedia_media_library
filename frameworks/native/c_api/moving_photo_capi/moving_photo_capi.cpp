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

#include "moving_photo_capi.h"

#include "oh_moving_photo.h"
#include "media_log.h"

MediaLibrary_ErrorCode OH_MovingPhoto_GetUri(OH_MovingPhoto* movingPhoto, const char** uri)
{
    CHECK_AND_RETURN_RET_LOG(movingPhoto != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "movingPhoto is nullptr!");
    CHECK_AND_RETURN_RET_LOG(movingPhoto->movingPhoto_ != nullptr,
        MEDIA_LIBRARY_OPERATION_NOT_SUPPORTED, "movingPhoto_ is nullptr!");
    CHECK_AND_RETURN_RET_LOG(uri != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "uri is nullptr!");

    return movingPhoto->movingPhoto_->GetUri(uri);
}

MediaLibrary_ErrorCode OH_MovingPhoto_RequestContentWithUris(OH_MovingPhoto* movingPhoto, char* imageUri,
    char* videoUri)
{
    CHECK_AND_RETURN_RET_LOG(movingPhoto != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "movingPhoto is nullptr!");
    CHECK_AND_RETURN_RET_LOG(movingPhoto->movingPhoto_ != nullptr,
        MEDIA_LIBRARY_OPERATION_NOT_SUPPORTED, "movingPhoto_ is nullptr!");
    CHECK_AND_RETURN_RET_LOG(imageUri != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "imageUri is nullptr!");
    CHECK_AND_RETURN_RET_LOG(videoUri != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "videoUri is nullptr!");

    return movingPhoto->movingPhoto_->RequestContentWithUris(imageUri, videoUri);
}

MediaLibrary_ErrorCode OH_MovingPhoto_RequestContentWithUri(OH_MovingPhoto* movingPhoto,
    MediaLibrary_ResourceType resourceType, char* uri)
{
    CHECK_AND_RETURN_RET_LOG(movingPhoto != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "movingPhoto is nullptr!");
    CHECK_AND_RETURN_RET_LOG(movingPhoto->movingPhoto_ != nullptr,
        MEDIA_LIBRARY_OPERATION_NOT_SUPPORTED, "movingPhoto_ is nullptr!");
    CHECK_AND_RETURN_RET_LOG(uri != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "uri is nullptr!");

    return movingPhoto->movingPhoto_->RequestContentWithUri(resourceType, uri);
}

MediaLibrary_ErrorCode OH_MovingPhoto_RequestContentWithBuffer(OH_MovingPhoto* movingPhoto,
    MediaLibrary_ResourceType resourceType, const uint8_t** buffer, uint32_t* size)
{
    CHECK_AND_RETURN_RET_LOG(movingPhoto != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "movingPhoto is nullptr!");
    CHECK_AND_RETURN_RET_LOG(movingPhoto->movingPhoto_ != nullptr,
        MEDIA_LIBRARY_OPERATION_NOT_SUPPORTED, "movingPhoto_ is nullptr!");
    CHECK_AND_RETURN_RET_LOG(buffer != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "buffer is nullptr!");
    CHECK_AND_RETURN_RET_LOG(size != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "size is nullptr!");

    return movingPhoto->movingPhoto_->RequestContentWithBuffer(resourceType, buffer, size);
}

MediaLibrary_ErrorCode OH_MovingPhoto_Release(OH_MovingPhoto* movingPhoto)
{
    CHECK_AND_RETURN_RET_LOG(movingPhoto != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "movingPhoto is nullptr!");

    delete movingPhoto;
    movingPhoto = nullptr;
    return MEDIA_LIBRARY_OK;
}
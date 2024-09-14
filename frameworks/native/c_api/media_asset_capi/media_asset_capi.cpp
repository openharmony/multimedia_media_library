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

#include "media_asset_capi.h"

#include "media_log.h"
#include "media_asset_impl.h"

MediaLibrary_ErrorCode OH_MediaAsset_GetUri(OH_MediaAsset* mediaAsset, const char** uri)
{
    CHECK_AND_RETURN_RET_LOG(mediaAsset != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "mediaAsset is nullptr!");
    CHECK_AND_RETURN_RET_LOG(uri != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "uri is nullptr!");

    return mediaAsset->GetUri(uri);
}

MediaLibrary_ErrorCode OH_MediaAsset_GetDisplayName(OH_MediaAsset* mediaAsset, const char** displayName)
{
    CHECK_AND_RETURN_RET_LOG(mediaAsset != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "mediaAsset is nullptr!");
    CHECK_AND_RETURN_RET_LOG(displayName != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "displayName is nullptr!");

    return mediaAsset->GetDisplayName(displayName);
}

MediaLibrary_ErrorCode OH_MediaAsset_GetSize(OH_MediaAsset* mediaAsset, uint32_t* size)
{
    CHECK_AND_RETURN_RET_LOG(mediaAsset != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "mediaAsset is nullptr!");
    CHECK_AND_RETURN_RET_LOG(size != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "size is nullptr!");

    return mediaAsset->GetSize(size);
}

MediaLibrary_ErrorCode OH_MediaAsset_GetDateModifiedMs(OH_MediaAsset* mediaAsset, uint32_t* dateModifiedMs)
{
    CHECK_AND_RETURN_RET_LOG(mediaAsset != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "mediaAsset is nullptr!");
    CHECK_AND_RETURN_RET_LOG(dateModifiedMs != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "dateModifiedMs is nullptr!");

    return mediaAsset->GetDateModifiedMs(dateModifiedMs);
}

MediaLibrary_ErrorCode OH_MediaAsset_GetWidth(OH_MediaAsset* mediaAsset, uint32_t* width)
{
    CHECK_AND_RETURN_RET_LOG(mediaAsset != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "mediaAsset is nullptr!");
    CHECK_AND_RETURN_RET_LOG(width != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "width is nullptr!");

    return mediaAsset->GetWidth(width);
}

MediaLibrary_ErrorCode OH_MediaAsset_GetHeight(OH_MediaAsset* mediaAsset, uint32_t* height)
{
    CHECK_AND_RETURN_RET_LOG(mediaAsset != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "mediaAsset is nullptr!");
    CHECK_AND_RETURN_RET_LOG(height != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "height is nullptr!");

    return mediaAsset->GetHeight(height);
}

MediaLibrary_ErrorCode OH_MediaAsset_GetOrientation(OH_MediaAsset* mediaAsset, uint32_t* orientation)
{
    CHECK_AND_RETURN_RET_LOG(mediaAsset != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "mediaAsset is nullptr!");
    CHECK_AND_RETURN_RET_LOG(orientation != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "orientation is nullptr!");

    return mediaAsset->GetOrientation(orientation);
}

MediaLibrary_ErrorCode OH_MediaAsset_Release(OH_MediaAsset* mediaAsset)
{
    CHECK_AND_RETURN_RET_LOG(mediaAsset != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "mediaAsset is nullptr!");

    delete mediaAsset;
    mediaAsset = nullptr;

    return MEDIA_LIBRARY_OK;
}
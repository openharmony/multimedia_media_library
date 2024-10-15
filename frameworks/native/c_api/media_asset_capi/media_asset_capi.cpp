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
#include "oh_media_asset.h"

MediaLibrary_ErrorCode OH_MediaAsset_GetUri(OH_MediaAsset* mediaAsset, const char** uri)
{
    CHECK_AND_RETURN_RET_LOG(mediaAsset != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "mediaAsset is nullptr!");
    CHECK_AND_RETURN_RET_LOG(mediaAsset->mediaAsset_ != nullptr,
        MEDIA_LIBRARY_OPERATION_NOT_SUPPORTED, "mediaAsset_ is nullptr!");
    CHECK_AND_RETURN_RET_LOG(uri != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "uri is nullptr!");

    return mediaAsset->mediaAsset_->GetUri(uri);
}

MediaLibrary_ErrorCode OH_MediaAsset_GetMediaType(OH_MediaAsset* mediaAsset, MediaLibrary_MediaType* mediaType)
{
    CHECK_AND_RETURN_RET_LOG(mediaAsset != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "mediaAsset is nullptr!");
    CHECK_AND_RETURN_RET_LOG(mediaAsset->mediaAsset_ != nullptr,
        MEDIA_LIBRARY_OPERATION_NOT_SUPPORTED, "mediaAsset_ is nullptr!");
    CHECK_AND_RETURN_RET_LOG(mediaType != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "mediaType is nullptr!");

    return mediaAsset->mediaAsset_->GetMediaType(mediaType);
}

MediaLibrary_ErrorCode OH_MediaAsset_GetMediaSubType(OH_MediaAsset* mediaAsset,
    MediaLibrary_MediaSubType* mediaSubType)
{
    CHECK_AND_RETURN_RET_LOG(mediaAsset != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "mediaAsset is nullptr!");
    CHECK_AND_RETURN_RET_LOG(mediaAsset->mediaAsset_ != nullptr,
        MEDIA_LIBRARY_OPERATION_NOT_SUPPORTED, "mediaAsset_ is nullptr!");
    CHECK_AND_RETURN_RET_LOG(mediaSubType != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "mediaSubType is nullptr!");

    return mediaAsset->mediaAsset_->GetMediaSubType(mediaSubType);
}

MediaLibrary_ErrorCode OH_MediaAsset_GetDisplayName(OH_MediaAsset* mediaAsset, const char** displayName)
{
    CHECK_AND_RETURN_RET_LOG(mediaAsset != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "mediaAsset is nullptr!");
    CHECK_AND_RETURN_RET_LOG(mediaAsset->mediaAsset_ != nullptr,
        MEDIA_LIBRARY_OPERATION_NOT_SUPPORTED, "mediaAsset_ is nullptr!");
    CHECK_AND_RETURN_RET_LOG(displayName != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "displayName is nullptr!");

    return mediaAsset->mediaAsset_->GetDisplayName(displayName);
}

MediaLibrary_ErrorCode OH_MediaAsset_GetSize(OH_MediaAsset* mediaAsset, uint32_t* size)
{
    CHECK_AND_RETURN_RET_LOG(mediaAsset != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "mediaAsset is nullptr!");
    CHECK_AND_RETURN_RET_LOG(mediaAsset->mediaAsset_ != nullptr,
        MEDIA_LIBRARY_OPERATION_NOT_SUPPORTED, "mediaAsset_ is nullptr!");
    CHECK_AND_RETURN_RET_LOG(size != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "size is nullptr!");

    return mediaAsset->mediaAsset_->GetSize(size);
}

MediaLibrary_ErrorCode OH_MediaAsset_GetDateAdded(OH_MediaAsset* mediaAsset, uint32_t* dateAdded)
{
    CHECK_AND_RETURN_RET_LOG(mediaAsset != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "mediaAsset is nullptr!");
    CHECK_AND_RETURN_RET_LOG(mediaAsset->mediaAsset_ != nullptr,
        MEDIA_LIBRARY_OPERATION_NOT_SUPPORTED, "mediaAsset_ is nullptr!");
    CHECK_AND_RETURN_RET_LOG(dateAdded != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "dateAdded is nullptr!");

    return mediaAsset->mediaAsset_->GetDateAdded(dateAdded);
}

MediaLibrary_ErrorCode OH_MediaAsset_GetDateModified(OH_MediaAsset* mediaAsset, uint32_t* dateModified)
{
    CHECK_AND_RETURN_RET_LOG(mediaAsset != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "mediaAsset is nullptr!");
    CHECK_AND_RETURN_RET_LOG(mediaAsset->mediaAsset_ != nullptr,
        MEDIA_LIBRARY_OPERATION_NOT_SUPPORTED, "mediaAsset_ is nullptr!");
    CHECK_AND_RETURN_RET_LOG(dateModified != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "dateModified is nullptr!");

    return mediaAsset->mediaAsset_->GetDateModified(dateModified);
}

MediaLibrary_ErrorCode OH_MediaAsset_GetDateTaken(OH_MediaAsset* mediaAsset, uint32_t* dateTaken)
{
    CHECK_AND_RETURN_RET_LOG(mediaAsset != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "mediaAsset is nullptr!");
    CHECK_AND_RETURN_RET_LOG(mediaAsset->mediaAsset_ != nullptr,
        MEDIA_LIBRARY_OPERATION_NOT_SUPPORTED, "mediaAsset_ is nullptr!");
    CHECK_AND_RETURN_RET_LOG(dateTaken != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "dateTaken is nullptr!");

    return mediaAsset->mediaAsset_->GetDateTaken(dateTaken);
}

MediaLibrary_ErrorCode OH_MediaAsset_GetDateAddedMs(OH_MediaAsset* mediaAsset, uint32_t* dateAddedMs)
{
    CHECK_AND_RETURN_RET_LOG(mediaAsset != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "mediaAsset is nullptr!");
    CHECK_AND_RETURN_RET_LOG(mediaAsset->mediaAsset_ != nullptr,
        MEDIA_LIBRARY_OPERATION_NOT_SUPPORTED, "mediaAsset_ is nullptr!");
    CHECK_AND_RETURN_RET_LOG(dateAddedMs != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "dateAddedMs is nullptr!");

    return mediaAsset->mediaAsset_->GetDateAddedMs(dateAddedMs);
}

MediaLibrary_ErrorCode OH_MediaAsset_GetDateModifiedMs(OH_MediaAsset* mediaAsset, uint32_t* dateModifiedMs)
{
    CHECK_AND_RETURN_RET_LOG(mediaAsset != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "mediaAsset is nullptr!");
    CHECK_AND_RETURN_RET_LOG(mediaAsset->mediaAsset_ != nullptr,
        MEDIA_LIBRARY_OPERATION_NOT_SUPPORTED, "mediaAsset_ is nullptr!");
    CHECK_AND_RETURN_RET_LOG(dateModifiedMs != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "dateModifiedMs is nullptr!");

    return mediaAsset->mediaAsset_->GetDateModifiedMs(dateModifiedMs);
}

MediaLibrary_ErrorCode OH_MediaAsset_GetDuration(OH_MediaAsset* mediaAsset, uint32_t* duration)
{
    CHECK_AND_RETURN_RET_LOG(mediaAsset != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "mediaAsset is nullptr!");
    CHECK_AND_RETURN_RET_LOG(mediaAsset->mediaAsset_ != nullptr,
        MEDIA_LIBRARY_OPERATION_NOT_SUPPORTED, "mediaAsset_ is nullptr!");
    CHECK_AND_RETURN_RET_LOG(duration != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "duration is nullptr!");

    return mediaAsset->mediaAsset_->GetDuration(duration);
}

MediaLibrary_ErrorCode OH_MediaAsset_GetWidth(OH_MediaAsset* mediaAsset, uint32_t* width)
{
    CHECK_AND_RETURN_RET_LOG(mediaAsset != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "mediaAsset is nullptr!");
    CHECK_AND_RETURN_RET_LOG(mediaAsset->mediaAsset_ != nullptr,
        MEDIA_LIBRARY_OPERATION_NOT_SUPPORTED, "mediaAsset_ is nullptr!");
    CHECK_AND_RETURN_RET_LOG(width != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "width is nullptr!");

    return mediaAsset->mediaAsset_->GetWidth(width);
}

MediaLibrary_ErrorCode OH_MediaAsset_GetHeight(OH_MediaAsset* mediaAsset, uint32_t* height)
{
    CHECK_AND_RETURN_RET_LOG(mediaAsset != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "mediaAsset is nullptr!");
    CHECK_AND_RETURN_RET_LOG(mediaAsset->mediaAsset_ != nullptr,
        MEDIA_LIBRARY_OPERATION_NOT_SUPPORTED, "mediaAsset_ is nullptr!");
    CHECK_AND_RETURN_RET_LOG(height != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "height is nullptr!");

    return mediaAsset->mediaAsset_->GetHeight(height);
}

MediaLibrary_ErrorCode OH_MediaAsset_GetOrientation(OH_MediaAsset* mediaAsset, uint32_t* orientation)
{
    CHECK_AND_RETURN_RET_LOG(mediaAsset != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "mediaAsset is nullptr!");
    CHECK_AND_RETURN_RET_LOG(mediaAsset->mediaAsset_ != nullptr,
        MEDIA_LIBRARY_OPERATION_NOT_SUPPORTED, "mediaAsset_ is nullptr!");
    CHECK_AND_RETURN_RET_LOG(orientation != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "orientation is nullptr!");

    return mediaAsset->mediaAsset_->GetOrientation(orientation);
}

MediaLibrary_ErrorCode OH_MediaAsset_IsFavorite(OH_MediaAsset* mediaAsset, uint32_t* favorite)
{
    CHECK_AND_RETURN_RET_LOG(mediaAsset != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "mediaAsset is nullptr!");
    CHECK_AND_RETURN_RET_LOG(mediaAsset->mediaAsset_ != nullptr,
        MEDIA_LIBRARY_OPERATION_NOT_SUPPORTED, "mediaAsset_ is nullptr!");
    CHECK_AND_RETURN_RET_LOG(favorite != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "favorite is nullptr!");

    return mediaAsset->mediaAsset_->IsFavorite(favorite);
}

MediaLibrary_ErrorCode OH_MediaAsset_GetTitle(OH_MediaAsset* mediaAsset, const char** title)
{
    CHECK_AND_RETURN_RET_LOG(mediaAsset != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "mediaAsset is nullptr!");
    CHECK_AND_RETURN_RET_LOG(mediaAsset->mediaAsset_ != nullptr,
        MEDIA_LIBRARY_OPERATION_NOT_SUPPORTED, "mediaAsset_ is nullptr!");
    CHECK_AND_RETURN_RET_LOG(title != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "title is nullptr!");

    return mediaAsset->mediaAsset_->GetTitle(title);
}

MediaLibrary_ErrorCode OH_MediaAsset_Release(OH_MediaAsset* mediaAsset)
{
    CHECK_AND_RETURN_RET_LOG(mediaAsset != nullptr, MEDIA_LIBRARY_PARAMETER_ERROR, "mediaAsset is nullptr!");

    delete mediaAsset;
    mediaAsset = nullptr;
    return MEDIA_LIBRARY_OK;
}
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

#include "media_asset_impl.h"

#include "media_log.h"
#include <securec.h>
#include "nocopyable.h"
#include "userfile_manager_types.h"

using namespace OHOS::Media;

const static int32_t MAX_URI_LENGTH = 256;
const static int32_t MAX_DISPLAY_NAME_LENGTH = MAX_URI_LENGTH + 6;

const std::unordered_map<MediaType, MediaLibrary_MediaType> g_mediaTypeMapping = {
    {MediaType::MEDIA_TYPE_IMAGE, MediaLibrary_MediaType::MEDIA_LIBRARY_IMAGE},
    {MediaType::MEDIA_TYPE_VIDEO, MediaLibrary_MediaType::MEDIA_LIBRARY_VIDEO},
};

const std::unordered_map<PhotoSubType, MediaLibrary_MediaSubType> g_photoSubTypeMapping = {
    {PhotoSubType::DEFAULT, MediaLibrary_MediaSubType::MEDIA_LIBRARY_DEFAULT},
    {PhotoSubType::MOVING_PHOTO, MediaLibrary_MediaSubType::MEDIA_LIBRARY_MOVING_PHOTO},
    {PhotoSubType::SUBTYPE_END, MediaLibrary_MediaSubType::MEDIA_LIBRARY_BURST},
};

OH_MediaAsset::OH_MediaAsset(std::shared_ptr<OHOS::Media::FileAsset> fileAsset)
{
    MEDIA_DEBUG_LOG("OH_MediaAsset Constructor is called.");
    fileAsset_ = fileAsset;
    uri_ = new char[MAX_URI_LENGTH];
    displayName_ = new char[MAX_DISPLAY_NAME_LENGTH];
}

OH_MediaAsset::~OH_MediaAsset()
{
    if (fileAsset_ != nullptr) {
        fileAsset_ = nullptr;
    }

    if (uri_ != nullptr) {
        delete[] uri_;
        uri_ = nullptr;
    }

    if (displayName_ != nullptr) {
        delete[] displayName_;
        displayName_ = nullptr;
    }
}

MediaLibrary_ErrorCode OH_MediaAsset::GetUri(const char** uri)
{
    if (uri_ == nullptr) {
        uri_ = new(std::nothrow) char[MAX_URI_LENGTH];
        CHECK_AND_RETURN_RET_LOG(uri_ != nullptr, MEDIA_LIBRARY_INTERNAL_SYSTEM_ERROR, "alloc memory failed!");
    }

    const std::string fileUri = fileAsset_->GetUri();
    int32_t uriLen = static_cast<int32_t>(fileUri.length());
    int32_t len = uriLen < MAX_URI_LENGTH ? uriLen : MAX_URI_LENGTH - 1;
    strncpy_s(uri_, MAX_URI_LENGTH, fileUri.c_str(), len);
    MEDIA_INFO_LOG("OH_MediaAsset::GetUri, uri: %{public}s, return uri: %{public}s",
        fileUri.c_str(), uri_);
    *uri = uri_;
    return MEDIA_LIBRARY_OK;
}

MediaLibrary_ErrorCode OH_MediaAsset::GetDisplayName(const char** displayName)
{
    if (displayName_ == nullptr) {
        displayName_ = new(std::nothrow) char[MAX_DISPLAY_NAME_LENGTH];
        CHECK_AND_RETURN_RET_LOG(displayName_ != nullptr, MEDIA_LIBRARY_INTERNAL_SYSTEM_ERROR, "alloc memory failed!");
    }

    const std::string display = fileAsset_->GetDisplayName();
    int32_t displayNameLen = static_cast<int32_t>(display.length());
    int32_t len = displayNameLen < MAX_DISPLAY_NAME_LENGTH ? displayNameLen : MAX_DISPLAY_NAME_LENGTH - 1;
    strncpy_s(displayName_, MAX_DISPLAY_NAME_LENGTH, display.c_str(), len);
    MEDIA_INFO_LOG("OH_MediaAsset::GetDisplayName, display name: %{public}s, return display name: %{public}s",
        display.c_str(), displayName_);
    *displayName = displayName_;
    return MEDIA_LIBRARY_OK;
}

MediaLibrary_ErrorCode OH_MediaAsset::GetSize(uint32_t* size)
{
    *size = static_cast<uint32_t>(fileAsset_->GetSize());
    return MEDIA_LIBRARY_OK;
}

MediaLibrary_ErrorCode OH_MediaAsset::GetDateModifiedMs(uint32_t* dateModifiedMs)
{
    *dateModifiedMs = static_cast<uint32_t>(fileAsset_->GetDateModified());
    return MEDIA_LIBRARY_OK;
}

std::shared_ptr<FileAsset> OH_MediaAsset::GetFileAssetInstance() const
{
    return fileAsset_;
}

MediaLibrary_ErrorCode OH_MediaAsset::GetWidth(uint32_t* width)
{
    *width = static_cast<uint32_t>(fileAsset_->GetWidth());
    return MEDIA_LIBRARY_OK;
}

MediaLibrary_ErrorCode OH_MediaAsset::GetHeight(uint32_t* height)
{
    *height = static_cast<uint32_t>(fileAsset_->GetHeight());
    return MEDIA_LIBRARY_OK;
}

MediaLibrary_ErrorCode OH_MediaAsset::GetOrientation(uint32_t* orientation)
{
    *orientation = static_cast<uint32_t>(fileAsset_->GetOrientation());
    return MEDIA_LIBRARY_OK;
}

/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef MEDIA_ALBUM_CHANGE_REQUES_IMPL_H
#define MEDIA_ALBUM_CHANGE_REQUES_IMPL_H

#include "ffi_remote_data.h"
#include "media_change_request_impl.h"
#include "photo_album_impl.h"

namespace OHOS {
namespace Media {
enum class AlbumChangeOperation {
    CREATE_ALBUM,
    ADD_ASSETS,
    REMOVE_ASSETS,
    MOVE_ASSETS,
    RECOVER_ASSETS,
    DELETE_ASSETS,
    SET_ALBUM_NAME,
    SET_COVER_URI,
    ORDER_ALBUM,
    SET_DISPLAY_LEVEL,
    MERGE_ALBUM,
    DISMISS_ASSET,
    SET_IS_ME,
    DISMISS,
};

class MediaAlbumChangeRequestImpl : public OHOS::FFI::FFIData, public MediaChangeRequestImpl {
    DECL_TYPE(MediaAlbumChangeRequestImpl, OHOS::FFI::FFIData)
public:
    MediaAlbumChangeRequestImpl() = default;
    ~MediaAlbumChangeRequestImpl() override = default;

    MediaAlbumChangeRequestImpl(shared_ptr<PhotoAlbum> photoAlbumPtr);
    int64_t CJGetAlbum(int32_t* errCode);
    int32_t CJSetAlbumName(std::string albumName);
    int32_t CJAddAssets(std::vector<std::string> assetUriArray);
    int32_t CJRemoveAssets(std::vector<std::string> assetUriArray);
    int32_t ApplyChanges() override;

    std::shared_ptr<PhotoAlbum> GetPhotoAlbumInstance() const;
    std::vector<std::string> GetAddAssetArray() const;
    std::vector<std::string> GetRemoveAssetArray() const;
    std::vector<AlbumChangeOperation> GetAlbumChangeOperations() const;
    void ClearAddAssetArray();
    void ClearRemoveAssetArray();

private:
    bool CheckChangeOperations();

    std::shared_ptr<PhotoAlbum> photoAlbum_ = nullptr;
    std::vector<std::string> assetsToAdd_;
    std::vector<std::string> assetsToRemove_;
    std::vector<AlbumChangeOperation> albumChangeOperations_;
};
} // namespace Media
} // namespace OHOS
#endif
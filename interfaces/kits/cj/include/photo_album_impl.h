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
#ifndef PHOTO_ALBUM_IMPL_H
#define PHOTO_ALBUM_IMPL_H

#include "photo_album.h"

#include "cj_ffi/cj_common_ffi.h"
#include "datashare_helper.h"
#include "datashare_values_bucket.h"
#include "fetch_result.h"
#include "file_asset.h"
#include "photo_accesshelper_utils.h"

namespace OHOS {
namespace Media {
class PhotoAlbumImpl : public OHOS::FFI::FFIData {
    DECL_TYPE(PhotoAlbumImpl, OHOS::FFI::FFIData)
public:
    explicit PhotoAlbumImpl(std::unique_ptr<PhotoAlbum> photoAlbumPtr_);
    ~PhotoAlbumImpl() override
    {
        photoAlbumPtr = nullptr;
    }
    std::shared_ptr<PhotoAlbum> GetPhotoAlbumInstance();
    int32_t GetPhotoAlbumType() const;
    int32_t GetPhotoAlbumSubType() const;
    std::string GetAlbumName() const;
    void SetAlbumName(char* cAlbumName);
    std::string GetAlbumUri() const;
    int32_t GetCount() const;
    std::string GetCoverUri() const;
    int32_t GetImageCount() const;
    int32_t GetVideoCount() const;
    std::shared_ptr<FetchResult<FileAsset>> GetAssets(COptions options, int32_t &errCode);
    void ParseArgsGetPhotoAssets(COptions options,  DataShare::DataSharePredicates &predicates,
       std::vector<std::string> &fetchColumn, ExtraInfo &extraInfo, int32_t &errCode);
    void CommitModify(int32_t &errCode);

private:
    std::shared_ptr<PhotoAlbum> photoAlbumPtr = nullptr;
};
}
}
#endif
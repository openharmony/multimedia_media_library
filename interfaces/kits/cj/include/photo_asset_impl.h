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
#ifndef PHOTO_ASSET_IMPL_H
#define PHOTO_ASSET_IMPL_H

#include <mutex>

#include "cj_ffi/cj_common_ffi.h"
#include "file_asset.h"
#include "ffi_remote_data.h"
#include "photo_accesshelper_utils.h"
#include "pixel_map.h"
#include "thumbnail_manager.h"
#include "userfile_manager_types.h"
#include "userfilemgr_uri.h"

namespace OHOS {
namespace Media {
class PhotoAssetImpl : public OHOS::FFI::FFIData {
    DECL_TYPE(PhotoAssetImpl, OHOS::FFI::FFIData)
public:
    explicit PhotoAssetImpl(std::shared_ptr<FileAsset> fileAssetPtr_);
    explicit PhotoAssetImpl(std::unique_ptr<FileAsset> fileAssetPtr_);
    ~PhotoAssetImpl() override
    {
        fileAssetPtr = nullptr;
    }
    std::shared_ptr<FileAsset> GetFileAssetInstance();
    std::string GetFileDisplayName();
    std::string GetFileUri();
    MediaType GetMediaType();
    int32_t GetFileId();

    PhotoAssetMember UserFileMgrGet(std::string &inputKey, int32_t &errCode);
    bool HandleParamSet(const std::string &inputKey, const std::string &value, ResultNapiType resultNapiType);
    void UserFileMgrSet(std::string &inputKey, std::string &value, int32_t &errCode);
    void CommitModify(int32_t &errCode);
    int64_t GetThumbnail(CSize cSize, int32_t &errCode);

private:
    std::shared_ptr<FileAsset> fileAssetPtr = nullptr;
};
}
}
#endif
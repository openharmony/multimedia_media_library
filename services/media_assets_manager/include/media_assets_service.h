/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_ASSETS_SERVICE_H
#define OHOS_MEDIA_ASSETS_SERVICE_H

#include <stdint.h>
#include <string>

#include "media_assets_rdb_operations.h"
#include "form_info_dto.h"
#include "commit_edited_asset_dto.h"
#include "create_asset_dto.h"
#include "clone_asset_dto.h"
#include "revert_to_original_dto.h"

namespace OHOS::Media {
class MediaAssetsService {
public:
    static MediaAssetsService &GetInstance();

    int32_t SaveFormInfo(const FormInfoDto& formInfoDto);
    int32_t SaveGalleryFormInfo(const FormInfoDto& formInfoDto);
    int32_t RemoveFormInfo(const std::string& formId);
    int32_t RemoveGalleryFormInfo(const std::string& formId);
    int32_t CommitEditedAsset(const CommitEditedAssetDto& commitEditedAssetDto);
    int32_t TrashPhotos(const std::vector<std::string> &uris);
    int32_t DeletePhotos(const std::vector<std::string> &uris);
    int32_t DeletePhotosCompleted(const std::vector<std::string> &fileIds);
    int32_t CreateAsset(CreateAssetDto &dto);
    int32_t CreateAssetForApp(CreateAssetDto &dto);
    int32_t CreateAssetForAppWithAlbum(CreateAssetDto &dto);
    int32_t CloneAsset(const CloneAssetDto& cloneAssetDto);
    int32_t RevertToOriginal(const RevertToOriginalDto& revertToOriginalDto);
private:
    MediaAssetsRdbOperations rdbOperation_;
};
} // namespace OHOS::Media
#endif // OHOS_MEDIA_ASSETS_SERVICE_H
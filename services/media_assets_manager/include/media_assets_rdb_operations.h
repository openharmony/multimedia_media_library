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

#ifndef OHOS_MEDIA_ASSETS_RDB_OPERATIONS_H
#define OHOS_MEDIA_ASSETS_RDB_OPERATIONS_H

#include <stdint.h>
#include <string>
#include <mutex>
#include <map>

#include "rdb_predicates.h"
#include "medialibrary_rdb_transaction.h"
#include "file_asset.h"
#include "medialibrary_operation.h"

namespace OHOS::Media {

class MediaAssetsRdbOperations {
public:
    MediaAssetsRdbOperations();
    ~MediaAssetsRdbOperations() = default;
    int32_t RemoveFormInfo(const std::string& formId);
    int32_t RemoveGalleryFormInfo(const std::string& formId);
    int32_t SaveFormInfo(const std::string& formId, const std::string& uri);
    int32_t SaveGalleryFormInfo(const std::vector<std::string>& formIds,
        const std::vector<std::string>& fileUris);
    int32_t RevertToOrigin(const int32_t &fileId);

    bool QueryAlbumIdIfExists(const std::string& albumId);
    bool QueryFileIdIfExists(const std::string& fileId);
    bool QueryFormIdIfExists(const std::string& formId);
    int32_t CommitEditInsert(const std::string& editData, int32_t fileId);
    static void DeleteFromVisionTables(const std::string& fileId);

private:
    static std::shared_ptr<FileAsset> GetFileAssetFromDb(const std::string &column, const std::string &value,
        OperationObject oprnObject, const std::vector<std::string> &columns = {}, const std::string &networkId = "");
    static std::mutex facardMutex_;
};

} // namespace OHOS::Media
#endif  // OHOS_MEDIA_ASSETS_RDB_OPERATIONS_H
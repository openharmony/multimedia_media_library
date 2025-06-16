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

#ifndef OHOS_MEDIALIBRARY_ASSET_DATA_MANAGER_H
#define OHOS_MEDIALIBRARY_ASSET_DATA_MANAGER_H

#include <string>
#include <vector>

#include "accurate_refresh_data_manager.h"
#include "abs_rdb_predicates.h"

#include "accurate_common_data.h"
#include "photo_asset_change_info.h"

namespace OHOS {
namespace Media::AccurateRefresh {
#define EXPORT __attribute__ ((visibility ("default")))

class EXPORT AssetDataManager : public AccurateRefreshDataManager<PhotoAssetChangeInfo, PhotoAssetChangeData> {
public:
    AssetDataManager() : AssetDataManager(nullptr)
    {}
    AssetDataManager(std::shared_ptr<TransactionOperations> trans)
        : AccurateRefreshDataManager<PhotoAssetChangeInfo, PhotoAssetChangeData>(trans)
    {}
    virtual ~AssetDataManager()
    {}
    int32_t UpdateModifiedDatas() override;
    int32_t PostProcessModifiedDatas(const std::vector<int32_t> &keys) override;
    std::vector<int32_t> GetInitKeys() override;
    int32_t SetContentChanged(int32_t fileId, bool isChanged);
    int32_t SetThumbnailStatus(int32_t fileId, int32_t status);
    int32_t UpdateNotifyInfo();

private:
    int32_t UpdateThumbnailChangeStatus(PhotoAssetChangeData &assetChangeData);
    int32_t GetChangeInfoKey(const PhotoAssetChangeInfo &changeInfo) override;
    std::vector<PhotoAssetChangeInfo> GetInfoByKeys(const std::vector<int32_t> &fileIds) override;
    std::vector<PhotoAssetChangeInfo> GetInfosByPredicates(const NativeRdb::AbsRdbPredicates &predicates) override;
    std::vector<PhotoAssetChangeInfo> GetInfosByResult(const std::shared_ptr<NativeRdb::ResultSet> &resultSet) override;

private:
    std::map<int32_t, PhotoAssetContentInfo> contentInfos;
};

}  // namespace Media::AccurateRefresh
}  // namespace OHOS

#endif
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

#ifndef OHOS_MEDIALIBRARY_ANALYSIS_ALBUM_ACCURATE_REFRESH_H
#define OHOS_MEDIALIBRARY_ANALYSIS_ALBUM_ACCURATE_REFRESH_H

#include <functional>
#include <string>
#include <vector>
#include <unordered_map>

#include "abs_rdb_predicates.h"
#include "accurate_refresh_base.h"
#include "album_change_info.h"
#include "analysis_album_batch_update_helper.h"
#include "analysis_album_change_notify_execution.h"
#include "analysis_album_data_manager.h"
#include "asset_data_manager.h"

namespace OHOS {
namespace Media {
namespace AccurateRefresh {
#define EXPORT __attribute__ ((visibility ("default")))

class EXPORT AnalysisAlbumAccurateRefresh : public AccurateRefreshBase {
public:
    AnalysisAlbumAccurateRefresh() : AccurateRefreshBase() {};
    AnalysisAlbumAccurateRefresh(std::shared_ptr<TransactionOperations> trans);
    AnalysisAlbumAccurateRefresh(const std::string &targetBusiness) : AccurateRefreshBase(targetBusiness, nullptr) {}
    AnalysisAlbumAccurateRefresh(const std::string &targetBusiness, std::shared_ptr<TransactionOperations> trans);
    virtual ~AnalysisAlbumAccurateRefresh() {}
    // init的查询语句
    int32_t Init() override;
    int32_t Init(const NativeRdb::AbsRdbPredicates &predicates) override;
    int32_t Init(const std::string &sql, const std::vector<NativeRdb::ValueObject> bindArgs) override;
    int32_t Init(const std::vector<int32_t> &albumIds) override;

    void InitForAdd(const std::vector<int> &albumIds);
    void InitForRemove(const std::vector<int> &albumIds);
    void GenerateDataAfterCustomizedUpdate(const vector<int> &albumIds);

    // 移除出智慧相册数据单点操作，更新智慧相册表并触发精准刷新与通知
    int32_t CustomUpdateAlbumsWithDeltaCount(int32_t deltaCount, const std::vector<std::string> &updateAlbumIds,
        const std::vector<std::string> &deletedAssetIds = {});

    void Notify();
    
    // 全量刷新情况下发送全量查询通知
    static void NotifyForAnalysisAssetReCheck();
    static void NotifyForAnalysisAlbumReCheck();

    void NotifyAnalysisAssetChange(const std::vector<int32_t> &assetIds, RdbOperation operation);
    void NotifyAnalysisPhotoChange(std::vector<PhotoAssetChangeData> &assetChangeDatas);
    void NotifyAnalysisAlbumChange(std::vector<AlbumChangeData> &albumChangeDatas);

protected:
    int32_t UpdateModifiedDatasInner(const std::vector<int> &albumIds, RdbOperation operation,
        PendingInfo pendingInfo = PendingInfo()) override;
    std::string GetReturningKeyName() override;
    bool IsValidTable(std::string tableName) override;
    void BuildRefreshItems(int32_t deltaCount, const std::vector<std::string> &updateAlbumIds,
        const std::vector<std::string> &deletedAssetIds, std::vector<BatchUpdateItem> &items);

private:
    AnalysisAlbumDataManager dataManager_;
    AnalysisAlbumChangeNotifyExecution notifyExe_;

    AssetDataManager assetDataManager_;
};
} // namespace AccurateRefresh
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_ANALYSIS_ALBUM_ACCURATE_REFRESH_H

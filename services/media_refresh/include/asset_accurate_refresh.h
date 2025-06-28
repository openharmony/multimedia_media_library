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

#ifndef OHOS_MEDIALIBRARY_ASSET_ACCURATE_REFRESH_H
#define OHOS_MEDIALIBRARY_ASSET_ACCURATE_REFRESH_H

#include <functional>
#include <string>
#include <vector>

#include "abs_rdb_predicates.h"

#include "medialibrary_rdb_utils.h"
#include "accurate_refresh_base.h"
#include "photo_asset_change_info.h"
#include "asset_data_manager.h"
#include "album_refresh_execution.h"
#include "asset_change_notify_execution.h"

namespace OHOS {
namespace Media::AccurateRefresh {
#define EXPORT __attribute__ ((visibility ("default")))

class EXPORT AssetAccurateRefresh : public AccurateRefreshBase {
public:
    using AccurateRefreshBase::Insert;
    using AccurateRefreshBase::BatchInsert;
    using AccurateRefreshBase::ExecuteSql;
    AssetAccurateRefresh() : AccurateRefreshBase(nullptr) {}
    AssetAccurateRefresh(std::shared_ptr<TransactionOperations> trans);
    virtual ~AssetAccurateRefresh() {}
    // 初始化datamanager，新增场景下使用，不需要初始化数据，Init只需要执行一次
    int32_t Init() override;

    // delete/update 场景下初始化数据，Init只需要执行一次
    int32_t Init(const NativeRdb::AbsRdbPredicates &predicates) override; // init的查询语句
    int32_t Init(const std::string &sql, const std::vector<NativeRdb::ValueObject> bindArgs) override; // 查询语句
    int32_t Init(const std::vector<int32_t> &fileIds) override; // 删除/更新指定fileIds场景使用

    // 更新modified数据信息；数据库操作只是缓存数据，需要执行这个函数触发对比修改前后的数据
    int32_t UpdateModifiedDatas();

    // refresh album based on init datas and modified datas.
    int32_t RefreshAlbum(NotifyAlbumType notifyAlbumType = NO_NOTIFY);
    
    // 根据传递的assetChangeDatas更新相册，不需要dataManager_处理
    int32_t RefreshAlbum(const std::vector<PhotoAssetChangeData> &assetChangeDatas,
        NotifyAlbumType notifyAlbumType = NO_NOTIFY);

    // notify assest change infos based on init datas and modified datas.
    int32_t Notify();

    // 根据传递的assetChangeDatas进行通知，不需要dataManager_处理
    int32_t Notify(const std::vector<PhotoAssetChangeData> &assetChangeDatas);
    using AccurateRefreshBase::LogicalDeleteReplaceByUpdate;
    int32_t LogicalDeleteReplaceByUpdate(MediaLibraryCommand &cmd, int32_t &deletedRows) override;
    int32_t LogicalDeleteReplaceByUpdate(const NativeRdb::AbsRdbPredicates &predicates, int32_t &deletedRows) override;

    int32_t Insert(MediaLibraryCommand &cmd, int64_t &outRowId) override;
    int32_t Insert(int64_t &outRowId, const std::string &table, NativeRdb::ValuesBucket &value) override;
    int32_t BatchInsert(int64_t &changedRows, const std::string &table,
        std::vector<NativeRdb::ValuesBucket> &values) override;
    int32_t ExecuteForLastInsertedRowId(const std::string &sql,
        const std::vector<NativeRdb::ValueObject> &bindArgs, RdbOperation operation) override;
    int32_t ExecuteSql(const std::string &sql,
        const std::vector<NativeRdb::ValueObject> &bindArgs, RdbOperation operation) override;
    int32_t ExecuteForChangedRowCount(int64_t &outValue, const std::string &sql,
        const std::vector<NativeRdb::ValueObject> &bindArgs, RdbOperation operation) override;

    int32_t SetContentChanged(int32_t fileId, bool isChanged);
    int32_t SetThumbnailStatus(int32_t fileId, int32_t status);
    static int32_t NotifyForReCheck();

protected:
    int32_t UpdateModifiedDatasInner(const std::vector<int> &fileIds, RdbOperation operation) override;
    std::string GetReturningKeyName() override;
    bool IsValidTable(std::string tableName) override;
    void SetDataManagerTransaction(std::shared_ptr<TransactionOperations> trans) override;
private:
    int32_t DeleteCommon(std::function<int32_t(NativeRdb::ValuesBucket &)> updateExe);

private:
    AssetDataManager dataManager_;
    AlbumRefreshExecution albumRefreshExe_;
    AssetChangeNotifyExecution notifyExe_;
};
} // namespace Media
} // namespace OHOS

#endif
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

#define MLOG_TAG "AccurateRefresh::AccurateRefreshDataManager"

#include "media_file_utils.h"
#include "accurate_refresh_data_manager.h"
#include "medialibrary_unistore_manager.h"
#include "accurate_debug_log.h"
#include "photo_asset_change_info.h"
#include "album_change_info.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media::AccurateRefresh {

template <typename ChangeInfo, typename ChangeData>
int32_t AccurateRefreshDataManager<ChangeInfo, ChangeData>::Init(const AbsRdbPredicates &predicates)
{
    auto initDatas = GetInfosByPredicates(predicates);
    if (initDatas.empty()) {
        MEDIA_WARN_LOG("init data empty");
        return ACCURATE_REFRESH_INIT_EMPTY;
    }
    return InsertInitChangeInfos(initDatas);
}

template <typename ChangeInfo, typename ChangeData>
int32_t AccurateRefreshDataManager<ChangeInfo, ChangeData>::Init(const string sql, const vector<ValueObject> bindArgs)
{
    if (sql.empty()) {
        MEDIA_WARN_LOG("input sql empty");
        return ACCURATE_REFRESH_INPUT_PARA_ERR;
    }

    shared_ptr<ResultSet> resultSet;
    if (trans_ != nullptr) {
        resultSet = trans_->QueryByStep(sql, bindArgs);
    } else {
        auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
        CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, ACCURATE_REFRESH_RDB_NULL, "rdbStore null");
        resultSet = rdbStore->QueryByStep(sql, bindArgs);
    }
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, ACCURATE_REFRESH_RDB_NULL, "resultSet null");

    auto initDatas = GetInfosByResult(resultSet);
    resultSet->Close();
    if (initDatas.empty()) {
        MEDIA_WARN_LOG("initDatas empty");
        return ACCURATE_REFRESH_INIT_EMPTY;
    }

    return InsertInitChangeInfos(initDatas);
}

template <typename ChangeInfo, typename ChangeData>
int32_t AccurateRefreshDataManager<ChangeInfo, ChangeData>::Init(const vector<int32_t> &keys)
{
    if (keys.empty()) {
        MEDIA_WARN_LOG("input keys empty");
        return ACCURATE_REFRESH_INPUT_PARA_ERR;
    }

    auto initDatas = GetInfoByKeys(keys);
    if (initDatas.empty()) {
        MEDIA_WARN_LOG("initDatas empty");
        return ACCURATE_REFRESH_INPUT_PARA_ERR;
    }
    
    return InsertInitChangeInfos(initDatas);
}

template <typename ChangeInfo, typename ChangeData>
int32_t AccurateRefreshDataManager<ChangeInfo, ChangeData>::UpdateModifiedDatasInner(const vector<int32_t> &keys,
    RdbOperation operation)
{
    if (keys.empty() || operation == RDB_OPERATION_UNDEFINED) {
        MEDIA_WARN_LOG("input keys empty or operation error");
        return ACCURATE_REFRESH_INPUT_PARA_ERR;
    }

    switch (operation) {
        case RDB_OPERATION_REMOVE:
            return UpdateModifiedDatasForRemove(keys);

        case RDB_OPERATION_ADD:
            return UpdateModifiedDatasForAdd(keys);

        case RDB_OPERATION_UPDATE:
            return UpdateModifiedDatasForUpdate(keys);

        default:
            return ACCURATE_REFRESH_INPUT_PARA_ERR;
    }
}

template <typename ChangeInfo, typename ChangeData>
int32_t AccurateRefreshDataManager<ChangeInfo, ChangeData>::InsertInitChangeInfos(
    const vector<ChangeInfo> &changeInfos)
{
    for (auto const &changeInfo : changeInfos) {
        auto key = GetChangeInfoKey(changeInfo);
        if (changeDatas_.find(key) != changeDatas_.end()) {
            // 数据重复：打印异常，不替换已有数据继续执行
            MEDIA_INFO_LOG("operate duplicate init key: %{public}d", key);
            continue;
        }
        ChangeData changeData;
        changeData.infoBeforeChange_ = changeInfo;
        changeDatas_.insert_or_assign(key, changeData); // 插入新值或者替换已有
    }

    return ACCURATE_REFRESH_RET_OK;
}

template <typename ChangeInfo, typename ChangeData>
int32_t AccurateRefreshDataManager<ChangeInfo, ChangeData>::CheckAndUpdateOperation(RdbOperation &newOperation,
    RdbOperation oldOperation)
{
    if (newOperation == RDB_OPERATION_UNDEFINED) {
        MEDIA_WARN_LOG("new operation undefined");
        return ACCURATE_REFRESH_INPUT_PARA_ERR;
    }

    if (oldOperation == RDB_OPERATION_UNDEFINED) {
        return ACCURATE_REFRESH_RET_OK;
    }

    // 增改场景支持，还是增
    if (oldOperation == RDB_OPERATION_ADD && newOperation == RDB_OPERATION_UPDATE) {
        newOperation = RDB_OPERATION_ADD;
        return ACCURATE_REFRESH_RET_OK;
    }

    // 改改场景支持
    if (oldOperation == RDB_OPERATION_UPDATE && newOperation == RDB_OPERATION_UPDATE) {
        return ACCURATE_REFRESH_RET_OK;
    }

    MEDIA_WARN_LOG("duplicate operation, oldOperation:%{public}d, newOperation:%{public}d",
        static_cast<int32_t>(oldOperation), static_cast<int32_t>(newOperation));
    return ACCURATE_REFRESH_RET_OK;
}

template <typename ChangeInfo, typename ChangeData>
int32_t AccurateRefreshDataManager<ChangeInfo, ChangeData>::UpdateModifiedDatasForRemove(const vector<int32_t> &keys)
{
    ACCURATE_DEBUG("keys size: %{public}zu", keys.size());
    for (auto key : keys) {
        auto iter = changeDatas_.find(key);
        if (iter == changeDatas_.end()) {
            MEDIA_WARN_LOG("not init info for remove.");
            return ACCURATE_REFRESH_MODIFIED_NO_INIT;
        }
        ChangeData &changeData = iter->second;
        RdbOperation operation = RDB_OPERATION_REMOVE;
        auto ret = CheckAndUpdateOperation(operation, changeData.operation_);
        if (ret != ACCURATE_REFRESH_RET_OK) {
            return ret;
        }
        changeData.operation_ = operation;
        changeData.isDelete_ = true;
        changeData.version_ = MediaFileUtils::UTCTimeMilliSeconds();
    }
    return ACCURATE_REFRESH_RET_OK;
}

template <typename ChangeInfo, typename ChangeData>
int32_t AccurateRefreshDataManager<ChangeInfo, ChangeData>::UpdateModifiedDatasForUpdate(const vector<int32_t> &keys)
{
    auto &modifiedKeys = keys;
    auto modifiedDatas = GetInfoByKeys(modifiedKeys);
    if (modifiedDatas.empty()) {
        MEDIA_WARN_LOG("modifiedDatas empty");
        return ACCURATE_REFRESH_MODIFY_EMPTY;
    }
    for (auto modifiedInfo : modifiedDatas) {
        // 找到key
        auto key = GetChangeInfoKey(modifiedInfo);
        // 根据key值，找changeData
        auto iter = changeDatas_.find(key);
        if (iter == changeDatas_.end()) {
            MEDIA_WARN_LOG("data no init.");
            return ACCURATE_REFRESH_MODIFIED_NO_INIT;
        }
        ChangeData &changeData = iter->second;

        // 更新operation
        RdbOperation operation = RDB_OPERATION_UPDATE;
        auto ret = CheckAndUpdateOperation(operation, changeData.operation_);
        if (ret != ACCURATE_REFRESH_RET_OK) {
            MEDIA_WARN_LOG("check operation wrong.");
            return ret;
        }
        changeData.operation_ = operation;
        changeData.version_ = MediaFileUtils::UTCTimeMilliSeconds();

        // 更新infoAfterChange_
        if (IsValidChangeInfo(changeData.infoAfterChange_)) {
            MEDIA_INFO_LOG("operate duplicate modified key: %{public}d", key);
        }
        changeData.infoAfterChange_ = modifiedInfo;
        ACCURATE_INFO("operation_: %{public}d isDelete: %{public}d", changeData.operation_, changeData.isDelete_);
        ACCURATE_INFO("before: %{public}s", changeData.infoBeforeChange_.ToString(true).c_str());
        ACCURATE_INFO("after: %{public}s", changeData.infoAfterChange_.ToString(true).c_str());
    }

    return ACCURATE_REFRESH_RET_OK;
}

template <typename ChangeInfo, typename ChangeData>
int32_t AccurateRefreshDataManager<ChangeInfo, ChangeData>::UpdateModifiedDatasForAdd(const vector<int32_t> &keys)
{
    ACCURATE_DEBUG("keys size: %{public}zu", keys.size());
    auto modifiedDatas = GetInfoByKeys(keys);
    if (modifiedDatas.empty()) {
        MEDIA_WARN_LOG("modifiedDatas empty");
        return ACCURATE_REFRESH_MODIFY_EMPTY;
    }
    for (auto &modifiedInfo : modifiedDatas) {
        // 找到key
        auto key = GetChangeInfoKey(modifiedInfo);
        // 根据key值，找changeData
        auto iter = changeDatas_.find(key);
        if (iter != changeDatas_.end()) {
            MEDIA_WARN_LOG("add already info, key: %{public}d", key);
            return ACCURATE_REFRESH_MODIFIED_ADD_NO_MATCH;
        }

        // 更新数据
        ChangeData changeData;
        changeData.infoAfterChange_ = modifiedInfo;
        changeData.operation_ = RDB_OPERATION_ADD;
        changeData.version_ = MediaFileUtils::UTCTimeMilliSeconds();
        changeDatas_.emplace(key, changeData);
    }

    return ACCURATE_REFRESH_RET_OK;
}

template <typename ChangeInfo, typename ChangeData>
bool AccurateRefreshDataManager<ChangeInfo, ChangeData>::IsValidChangeInfo(const ChangeInfo &changeInfo)
{
    return GetChangeInfoKey(changeInfo) != INVALID_INT32_VALUE;
}

template <typename ChangeInfo, typename ChangeData>
vector<ChangeData> AccurateRefreshDataManager<ChangeInfo, ChangeData>::GetChangeDatas()
{
    vector<ChangeData> changeDatas;
    for (const auto &data: changeDatas_) {
        changeDatas.push_back(data.second);
    }
    return changeDatas;
}

template <typename ChangeInfo, typename ChangeData>
void AccurateRefreshDataManager<ChangeInfo, ChangeData>::SetTransaction(std::shared_ptr<TransactionOperations> trans)
{
    trans_ = trans;
}
template class AccurateRefreshDataManager<PhotoAssetChangeInfo, PhotoAssetChangeData>;
template class AccurateRefreshDataManager<AlbumChangeInfo, AlbumChangeData>;

} // namespace Media
} // namespace OHOS
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

#ifndef OHOS_MEDIALIBRARY_ACCURATE_REFRESH_DATA_MANAGER_H
#define OHOS_MEDIALIBRARY_ACCURATE_REFRESH_DATA_MANAGER_H

#include <string>
#include <map>

#include "abs_rdb_predicates.h"
#include "result_set.h"
#include "accurate_common_data.h"
#include "medialibrary_rdb_transaction.h"

namespace OHOS {
namespace Media::AccurateRefresh {
#define EXPORT __attribute__ ((visibility ("default")))

template <typename ChangeInfo, typename ChangeData>
class EXPORT AccurateRefreshDataManager {
public:
    AccurateRefreshDataManager(std::shared_ptr<TransactionOperations> trans): trans_(trans) {}
    // init的查询语句，Init只需要执行一次
    int32_t Init(const NativeRdb::AbsRdbPredicates &predicates);
    int32_t Init(const std::string sql, const std::vector<NativeRdb::ValueObject> bindArgs);
    // delete/update场景下初始化数据
    int32_t Init(const std::vector<int32_t> &keys);

    virtual int32_t UpdateModifiedDatas() = 0;
    int32_t UpdateModifiedDatasInner(const std::vector<int32_t> &keys, RdbOperation operation,
        PendingInfo &pendingInfo);
    virtual int32_t PostProcessModifiedDatas(const std::vector<int32_t> &keys) = 0;
    // 根据isCheckUpdate在数据获取时进行一次刷新处理，解决多线程问题
    std::vector<ChangeData> GetChangeDatas(bool isCheckUpdate = false);
    virtual std::vector<int32_t> GetInitKeys() = 0;
    void SetTransaction(std::shared_ptr<TransactionOperations> trans);
    // 外部接口数据无法获取修改前后数据进行精准计算
    bool CheckIsForRecheck();
    bool CanTransOperate();
 
protected:
    int32_t InsertInitChangeInfos(const std::vector<ChangeInfo> &changeInfos, PendingInfo pendingInfo = PendingInfo());
    bool CheckIsExceed(bool isLengthChanged = false);
    bool CheckIsExceed(std::size_t length);

private:
    int32_t CheckAndUpdateOperation(RdbOperation &newOperation, RdbOperation oldOperation);
    int32_t UpdateModifiedDatasForRemove(const std::vector<int32_t> &keys, PendingInfo &pendingInfo);
    int32_t UpdateModifiedDatasForUpdate(const std::vector<int32_t> &keys, PendingInfo &pendingInfo);
    int32_t UpdateModifiedDatasForAdd(const std::vector<int32_t> &keys, PendingInfo &pendingInfo);
    bool IsValidChangeInfo(const ChangeInfo &changeInfo);

    virtual int32_t GetChangeInfoKey(const ChangeInfo &changeInfo) = 0;
    virtual std::vector<ChangeInfo> GetInfoByKeys(const std::vector<int32_t> &keys) = 0;
    virtual std::vector<ChangeInfo> GetInfosByPredicates(const NativeRdb::AbsRdbPredicates &predicates) = 0;
    virtual std::vector<ChangeInfo> GetInfosByResult(const std::shared_ptr<NativeRdb::ResultSet> &resultSet) = 0;
    std::size_t GetCurrentDataLength();
    // before数据插入后处理
    virtual void PostInsertBeforeData(ChangeData &changeData, PendingInfo &pendingInfo) {}
    // after数据插入后处理
    virtual void PostInsertAfterData(ChangeData &changeData, PendingInfo &pendingInfo, bool isAdd = false) {}
    // 资产数据在更新相册时，可能需要刷新，解决多线程问题
    virtual bool CheckUpdateDataForMultiThread(ChangeData &changeData) { return false; }

protected:
    std::map<int32_t, ChangeData> changeDatas_;
    std::shared_ptr<TransactionOperations> trans_;
    bool isExceed_ = false;
    bool isForRecheck_ = false;
};

} // namespace Media
} // namespace OHOS

#endif
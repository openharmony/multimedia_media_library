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

template <typename ChangeInfo, typename ChangeData>
class AccurateRefreshDataManager {
public:
    AccurateRefreshDataManager(std::shared_ptr<TransactionOperations> trans): trans_(trans) {}
    // init的查询语句，Init只需要执行一次
    int32_t Init(const NativeRdb::AbsRdbPredicates &predicates);
    int32_t Init(const std::string sql, const std::vector<NativeRdb::ValueObject> bindArgs);
    // delete/update场景下初始化数据
    int32_t Init(const std::vector<int32_t> &keys);

    virtual int32_t UpdateModifiedDatas() = 0;
    int32_t UpdateModifiedDatasInner(const std::vector<int32_t> &keys, RdbOperation operation);
    std::vector<ChangeData> GetChangeDatas();
    virtual std::vector<int32_t> GetInitKeys() = 0;
 
protected:
    int32_t InsertInitChangeInfos(const std::vector<ChangeInfo> &changeInfos);

private:
    int32_t CheckAndUpdateOperation(RdbOperation &newOperation, RdbOperation oldOperation);
    virtual int32_t UpdateModifiedDatasForRemove(const std::vector<int32_t> keys);
    virtual int32_t UpdateModifiedDatasForUpdate(const std::vector<int32_t> keys);
    virtual int32_t UpdateModifiedDatasForAdd(const std::vector<int32_t> keys);
    bool IsValidChangeInfo(const ChangeInfo &changeInfo);

    virtual int32_t GetChangeInfoKey(const ChangeInfo &changeInfo) = 0;
    virtual std::vector<ChangeInfo> GetInfoByKeys(const std::vector<int32_t> &keys) = 0;
    virtual std::vector<ChangeInfo> GetInfosByPredicates(const NativeRdb::AbsRdbPredicates &predicates) = 0;
    virtual std::vector<ChangeInfo> GetInfosByResult(const std::shared_ptr<NativeRdb::ResultSet> &resultSet) = 0;

protected:
    std::map<int32_t, ChangeData> changeDatas_;
    std::shared_ptr<TransactionOperations> trans_;
};

} // namespace Media
} // namespace OHOS

#endif
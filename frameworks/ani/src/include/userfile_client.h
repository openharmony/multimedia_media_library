/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_ANI_SRC_INCLUDE_USER_FILE_CLIENT_H
#define FRAMEWORKS_ANI_SRC_INCLUDE_USER_FILE_CLIENT_H

#include <memory>
#include <string>
#include <vector>

#include "ani_error.h"
#include "datashare_helper.h"
#include "rdb_store.h"
#include "uri.h"
#include "safe_map.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
class UserFileClient {
public:
    EXPORT UserFileClient() {}
    EXPORT virtual ~UserFileClient() {}
    EXPORT static bool IsValid(const int32_t userId = -1);
    EXPORT static ani_status CheckIsStage(ani_env *env, ani_object object, bool &result);
    EXPORT static sptr<IRemoteObject> ParseTokenInStageMode(ani_env *env, ani_object object);

    EXPORT static void Init(const sptr<IRemoteObject> &token, bool isSetHelper = false, const int32_t userId = -1);
    EXPORT static void Init(ani_env *env, ani_object object, const int32_t userId = -1);
    EXPORT static std::shared_ptr<DataShare::DataShareResultSet> Query(Uri &uri,
        const DataShare::DataSharePredicates &predicates, std::vector<std::string> &columns,
        int &errCode, const int32_t userId = -1);
    EXPORT static int Insert(Uri &uri, const DataShare::DataShareValuesBucket &value, const int32_t userId = -1);
    EXPORT static int InsertExt(Uri &uri, const DataShare::DataShareValuesBucket &value, std::string &result,
        const int32_t userId = -1);
    EXPORT static int BatchInsert(Uri &uri, const std::vector<DataShare::DataShareValuesBucket> &values);
    EXPORT static int Delete(Uri &uri, const DataShare::DataSharePredicates &predicates);
    EXPORT static void NotifyChange(const Uri &uri);
    EXPORT static void RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver);
    EXPORT static void UnregisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver);
    EXPORT static int OpenFile(Uri &uri, const std::string &mode, const int32_t userId = -1);
    EXPORT static int Update(Uri &uri, const DataShare::DataSharePredicates &predicates,
        const DataShare::DataShareValuesBucket &value, const int32_t userId = -1);
    EXPORT static void RegisterObserverExt(const Uri &uri,
        std::shared_ptr<DataShare::DataShareObserver> dataObserver, bool isDescendants);
    EXPORT static void UnregisterObserverExt(const Uri &uri,
        std::shared_ptr<DataShare::DataShareObserver> dataObserver);
    EXPORT static void Clear();
    EXPORT static std::shared_ptr<NativeRdb::ResultSet> QueryRdb(Uri &uri,
        const DataShare::DataSharePredicates &predicates, std::vector<std::string> &columns);
    EXPORT static std::string GetType(Uri &uri);
    EXPORT static int32_t UserDefineFunc(const int32_t &userId, MessageParcel &data, MessageParcel &reply,
        MessageOption &option);
    EXPORT static void SetUserId(const int32_t userId);
    EXPORT static int32_t GetUserId();
    EXPORT static std::shared_ptr<DataShare::DataShareHelper> GetDataShareHelperByUser(const int32_t userId);
private:
    static std::shared_ptr<DataShare::DataShareHelper> GetDataShareHelper(ani_env *env,
        ani_object object, const int32_t userId);
    static int32_t userId_;
    static SafeMap<int32_t, std::shared_ptr<DataShare::DataShareHelper>> dataShareHelperMap_;
};
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_ANI_SRC_INCLUDE_USER_FILE_CLIENT_H
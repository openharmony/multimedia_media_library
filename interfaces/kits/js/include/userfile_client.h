/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_USER_FILE_CLIENT_H
#define INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_USER_FILE_CLIENT_H

#include "datashare_helper.h"
#include "datashare_predicates.h"
#include "message_parcel.h"
#include "napi_base_context.h"
#include "message_parcel.h"
#include "napi_error.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_remote_object.h"
#include "rdb_store.h"
#include "uri.h"
#include "safe_map.h"
#include "bundle_mgr_interface.h"
#include <mutex>

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
class UserFileClient {
public:
    EXPORT UserFileClient() {}
    EXPORT virtual ~UserFileClient() {}
    EXPORT static bool IsValid(const int32_t userId = -1);
    EXPORT static napi_status CheckIsStage(napi_env env, napi_callback_info info, bool &result);
    EXPORT static sptr<IRemoteObject> ParseTokenInStageMode(napi_env env, napi_callback_info info);
    EXPORT static sptr<IRemoteObject> ParseTokenInAbility(napi_env env, napi_callback_info info);

    EXPORT static void Init(const sptr<IRemoteObject> &token, bool isSetHelper = false, const int32_t userId = -1);
    EXPORT static void Init(napi_env env, napi_callback_info info, const int32_t userId = -1);
    EXPORT static std::shared_ptr<DataShare::DataShareResultSet> Query(Uri &uri,
        const DataShare::DataSharePredicates &predicates, std::vector<std::string> &columns,
        int &errCode, const int32_t userId = -1);
    EXPORT static std::pair<bool, std::shared_ptr<DataShare::DataShareResultSet>> QueryAccessibleViaSandBox(Uri &uri,
        const DataShare::DataSharePredicates &predicates, std::vector<std::string> &columns, int &errCode,
        const int32_t userId = -1);
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
    EXPORT static int32_t UserDefineFunc(MessageParcel &data, MessageParcel &reply, MessageOption &option);
    EXPORT static int32_t UserDefineFunc(const int32_t &userId, MessageParcel &data, MessageParcel &reply,
        MessageOption &option);
    EXPORT static void SetUserId(const int32_t userId);
    EXPORT static int32_t GetUserId();
    EXPORT static std::shared_ptr<DataShare::DataShareHelper> GetDataShareHelperByUser(const int32_t userId);
    EXPORT static std::string GetBundleName();
    EXPORT static int32_t RegisterObserverExtProvider(const Uri &uri,
        std::shared_ptr<DataShare::DataShareObserver> dataObserver, bool isDescendants);
    EXPORT static int32_t UnregisterObserverExtProvider(const Uri &uri,
        std::shared_ptr<DataShare::DataShareObserver> dataObserver);

private:
    static inline std::shared_ptr<DataShare::DataShareHelper> sDataShareHelper_ = nullptr;
    static std::shared_ptr<DataShare::DataShareHelper> GetDataShareHelper(napi_env env, napi_callback_info info,
        const int32_t userId = -1);
    static int32_t userId_;
    static std::string bundleName_;
    static SafeMap<int32_t, std::shared_ptr<DataShare::DataShareHelper>> dataShareHelperMap_;
    static sptr<AppExecFwk::IBundleMgr> GetSysBundleManager();
    static sptr<AppExecFwk::IBundleMgr> bundleMgr_;
    static std::mutex bundleMgrMutex_;
};
}
}

#endif // INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_USER_FILE_CLIENT_H
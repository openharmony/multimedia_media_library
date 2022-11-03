/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "napi_base_context.h"
#include "napi_error.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_remote_object.h"
#include "uri.h"

namespace OHOS {
namespace Media {
class UserFileClient {
public:
    UserFileClient() {}
    virtual ~UserFileClient() {}
    static bool IsValid();
    static void Init(napi_env env, napi_callback_info info);
    static std::shared_ptr<DataShare::DataShareResultSet> Query(Uri &uri,
        const DataShare::DataSharePredicates &predicates, std::vector<std::string> &columns);
    static int Insert(Uri &uri, const DataShare::DataShareValuesBucket &value);
    static int Delete(Uri &uri, const DataShare::DataSharePredicates &predicates);
    static void NotifyChange(const Uri &uri);
    static void RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver);
    static void UnregisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver);
    static int OpenFile(Uri &uri, const std::string &mode);
    static int Update(Uri &uri, const DataShare::DataSharePredicates &predicates,
        const DataShare::DataShareValuesBucket &value);
private:
    static inline std::shared_ptr<DataShare::DataShareHelper> sDataShareHelper_ = nullptr;
    static std::shared_ptr<DataShare::DataShareHelper> GetDataShareHelper(napi_env env, napi_callback_info info);
};
}
}

#endif // INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_USER_FILE_CLIENT_H
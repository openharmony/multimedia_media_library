/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef USERFILE_CLIENT_H
#define USERFILE_CLIENT_H

#include "datashare_helper.h"
#include "datashare_predicates.h"
#include "medialibrary_helper_container.h"
#include "photo_accesshelper_log.h"
#include "uri.h"

namespace OHOS {
namespace Media {

class UserFileClient {
public:
    UserFileClient() {}
    virtual ~UserFileClient() {}
    static bool IsValid();

    static void Init(const sptr<IRemoteObject> &token);
    static void Init(int64_t contextId);
    static std::shared_ptr<DataShare::DataShareResultSet> Query(Uri &uri,
        const DataShare::DataSharePredicates &predicates, std::vector<std::string> &columns, int &errCode);
    static int Insert(Uri &uri, const DataShare::DataShareValuesBucket &value);
    static int InsertExt(Uri &uri, const DataShare::DataShareValuesBucket &value, std::string &result);
    static int BatchInsert(Uri& uri, const std::vector<DataShare::DataShareValuesBucket>& values);
    static int Update(Uri &uri, const DataShare::DataSharePredicates &predicates,
        const DataShare::DataShareValuesBucket &value);
    static int Delete(Uri &uri, const DataShare::DataSharePredicates &predicates);
    static void NotifyChange(const Uri &uri);
    static void RegisterObserverExt(const Uri &uri,
        std::shared_ptr<DataShare::DataShareObserver> dataObserver, bool isDescendants);
    static void UnregisterObserverExt(const Uri &uri,
        std::shared_ptr<DataShare::DataShareObserver> dataObserver);
    static void RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver);
    static void UnregisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver);
    static int OpenFile(Uri &uri, const std::string &mode);
    static void SetUserId(const int32_t userId);
    static int32_t GetUserId();
    static void SetLastUserId(const int32_t userId);
    static int32_t GetLastUserId();

private:
    static inline std::shared_ptr<DataShare::DataShareHelper> sDataShareHelper_ = nullptr;
    static int32_t userId_;
    static int32_t lastUserId_;
};
}
}
#endif
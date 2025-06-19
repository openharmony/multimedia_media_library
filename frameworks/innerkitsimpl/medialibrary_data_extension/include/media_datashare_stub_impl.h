/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef DATASHARE_STUB_IMPL_H
#define DATASHARE_STUB_IMPL_H

#include <memory>
#include "datashare_stub.h"
#include "media_datashare_ext_ability.h"
#include "native_engine/native_value.h"
#include "i_observer_manager_interface.h"
#include "media_observer_manager.h"

namespace OHOS {
namespace DataShare {
using DataShare::MediaDataShareExtAbility;
#define EXPORT __attribute__ ((visibility ("default")))
class EXPORT MediaDataShareStubImpl : public DataShareStub {
public:
    EXPORT explicit MediaDataShareStubImpl(const std::shared_ptr<MediaDataShareExtAbility>& extension, napi_env env)
        : extension_(extension)
    {
    }

    EXPORT virtual ~MediaDataShareStubImpl() {}

    EXPORT std::vector<std::string> GetFileTypes(const Uri &uri, const std::string &mimeTypeFilter) override;

    EXPORT int OpenFile(const Uri &uri, const std::string &mode) override;

    EXPORT int OpenRawFile(const Uri &uri, const std::string &mode) override;

    EXPORT int Insert(const Uri &uri, const DataShareValuesBucket &value) override;

    EXPORT int InsertExt(const Uri &uri, const DataShareValuesBucket &value, std::string &result) override;

    EXPORT int Update(const Uri &uri, const DataSharePredicates &predicates,
        const DataShareValuesBucket &value) override;

    EXPORT int Delete(const Uri &uri, const DataSharePredicates &predicates) override;

    EXPORT std::shared_ptr<DataShareResultSet> Query(const Uri &uri, const DataSharePredicates &predicates,
        std::vector<std::string> &columns, DatashareBusinessError &businessError) override;

    EXPORT std::string GetType(const Uri &uri) override;

    EXPORT int BatchInsert(const Uri &uri, const std::vector<DataShareValuesBucket> &values) override;

    EXPORT bool RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver) override;

    EXPORT bool UnregisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver) override;

    EXPORT int RegisterObserverExtProvider(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver,
        bool isDescendants) override;

    EXPORT int UnregisterObserverExtProvider(const Uri &uri,
        const sptr<AAFwk::IDataAbilityObserver> &dataObserver) override;

    EXPORT bool NotifyChange(const Uri &uri) override;

    EXPORT Uri NormalizeUri(const Uri &uri) override;

    EXPORT Uri DenormalizeUri(const Uri &uri) override;

    EXPORT int32_t UserDefineFunc(MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    EXPORT std::shared_ptr<MediaDataShareExtAbility> GetOwner();

private:
    std::shared_ptr<MediaDataShareExtAbility> extension_;
};
} // namespace DataShare
} // namespace OHOS
#endif // DATASHARE_STUB_IMPL_H


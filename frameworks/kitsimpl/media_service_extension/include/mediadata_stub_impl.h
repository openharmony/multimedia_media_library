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

#ifndef OHOS_MEDIALIBRARY_MEDIADATA_STUB_IMPL_H
#define OHOS_MEDIALIBRARY_MEDIADATA_STUB_IMPL_H

#include <memory>
#include "mediadata_stub.h"
#include "mediadata_uv_queue.h"
#include "native_engine/native_value.h"
#include "context.h"
#include "foundation/aafwk/standard/frameworks/kits/appkit/native/ability_runtime/context/context.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store.h"
#include "rdb_store_config.h"
#include "rdb_types.h"

namespace OHOS {
namespace AppExecFwk {
class MediaDataStubImpl : public MediaDataStub {
public:
    explicit MediaDataStubImpl(napi_env env, std::shared_ptr<AbilityRuntime::Context> &context)
    {
	context_ = context;
        uvQueue_ = std::make_shared<AbilityRuntime::MediaDataUvQueue>(env);
    }

    virtual ~MediaDataStubImpl() {}

    std::vector<std::string> GetFileTypes(const Uri &uri, const std::string &mimeTypeFilter) override;

    int OpenFile(const Uri &uri, const std::string &mode) override;

    int OpenRawFile(const Uri &uri, const std::string &mode) override;

    int Insert(const Uri &uri, const NativeRdb::ValuesBucket &value) override;

    int Update(const Uri &uri, const NativeRdb::ValuesBucket &value,
        const NativeRdb::DataAbilityPredicates &predicates) override;

    int Delete(const Uri &uri, const NativeRdb::DataAbilityPredicates &predicates) override;

    std::shared_ptr<NativeRdb::AbsSharedResultSet> Query(const Uri &uri,
        std::vector<std::string> &columns, const NativeRdb::DataAbilityPredicates &predicates) override;

    std::string GetType(const Uri &uri) override;

    int BatchInsert(const Uri &uri, const std::vector<NativeRdb::ValuesBucket> &values) override;

    bool RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver) override;

    bool UnregisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver) override;

    bool NotifyChange(const Uri &uri) override;

    Uri NormalizeUri(const Uri &uri) override;

    Uri DenormalizeUri(const Uri &uri) override;

    std::vector<std::shared_ptr<AppExecFwk::DataAbilityResult>> ExecuteBatch(
        const std::vector<std::shared_ptr<AppExecFwk::DataAbilityOperation>> &operations) override;

    int32_t InitMediaLibraryRdbStore();
private:
    std::shared_ptr<AbilityRuntime::MediaDataUvQueue> uvQueue_;
    //std::shared_ptr<NativeRdb::RdbStore> rdbStore_;
    std::shared_ptr<AbilityRuntime::Context> context_ = nullptr;
    
   // bool isRdbStoreInitialized = false;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_MEDIADATA_STUB_IMPL_H


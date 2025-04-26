/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "medialibraryextension_fuzzer.h"

#include <cstdint>
#include <memory>
#include <string>
#include <thread>

#include "ability_context_impl.h"
#include "data_ability_observer_interface.h"
#include "datashare_business_error.h"
#include "datashare_helper.h"
#include "datashare_predicates.h"
#include "datashare_values_bucket.h"
#include "media_datashare_ext_ability.h"
#include "medialibrary_data_manager.h"
#include "media_datashare_stub_impl.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "runtime.h"

namespace OHOS {
using namespace std;
using namespace AbilityRuntime;
using namespace DataShare;

static inline int32_t FuzzInt32(const uint8_t *data, size_t size)
{
    return static_cast<int32_t>(*data);
}

static inline int64_t FuzzInt64(const uint8_t *data, size_t size)
{
    return static_cast<int64_t>(*data);
}

static inline double FuzzDouble(const uint8_t *data, size_t size)
{
    return static_cast<double>(*data);
}

static inline string FuzzString(const uint8_t *data, size_t size)
{
    return {reinterpret_cast<const char*>(data), size};
}

static inline vector<int32_t> FuzzVectorInt32(const uint8_t *data, size_t size)
{
    return {FuzzInt32(data, size)};
}

static inline vector<int64_t> FuzzVectorInt64(const uint8_t *data, size_t size)
{
    return {FuzzInt64(data, size)};
}

static inline vector<double> FuzzVectorDouble(const uint8_t *data, size_t size)
{
    return {FuzzDouble(data, size)};
}

static inline vector<string> FuzzVectorString(const uint8_t *data, size_t size)
{
    return {FuzzString(data, size)};
}

static inline vector<SingleValue::Type> FuzzVectorSingleValueType(const uint8_t *data, size_t size)
{
    return {FuzzInt64(data, size)};
}

static inline vector<MutliValue::Type> FuzzVectorMultiValueType(const uint8_t *data, size_t size)
{
    return {
        FuzzVectorInt32(data, size),
        FuzzVectorInt64(data, size),
        FuzzVectorString(data, size),
        FuzzVectorDouble(data, size)
    };
}

static inline OperationItem FuzzOperationItem(const uint8_t *data, size_t size)
{
    return {
        .operation = FuzzInt32(data, size),
        .singleParams = FuzzVectorSingleValueType(data, size),
        .multiParams = FuzzVectorMultiValueType(data, size),
    };
}

static inline vector<OperationItem> FuzzVectorOperationItem(const uint8_t *data, size_t size)
{
    return {FuzzOperationItem(data, size)};
}

static inline Uri FuzzUri(const uint8_t *data, size_t size)
{
    uint8_t length = static_cast<uint8_t>(Media::EXTENSION_FUZZER_URI_LISTS.size());
    if (*data < length) {
        return Uri(Media::EXTENSION_FUZZER_URI_LISTS[*data]);
    }
    return Uri("Undefined");
}

static inline DataSharePredicates FuzzDataSharePredicates(const uint8_t *data, size_t size)
{
    return DataSharePredicates(FuzzVectorOperationItem(data, size));
}

static inline DataShareValuesBucket FuzzDataShareValuesBucket()
{
    return {};
}

static inline vector<DataShareValuesBucket> FuzzVectorDataShareValuesBucket()
{
    return {FuzzDataShareValuesBucket()};
}

static inline DatashareBusinessError FuzzDataShareBusinessError(const uint8_t *data, size_t size)
{
    DatashareBusinessError error;
    error.SetCode(FuzzInt32(data, size));
    error.SetMessage(FuzzString(data, size));
    return error;
}

static inline string FuzzOpenMode(const uint8_t *data, size_t size)
{
    uint8_t length = static_cast<uint8_t>(Media::MEDIA_OPEN_MODES.size());
    if (*data < length) {
        auto it = Media::MEDIA_OPEN_MODES.begin();
        std::advance(it, *data);
        return *it;
    }
    return "";
}

// function
static inline void CreateFuzzer(MediaDataShareExtAbility &extension)
{
    const std::unique_ptr<AbilityRuntime::Runtime> runtime;
    extension.Create(runtime);
}

static inline void GetFileTypesFuzzer(MediaDataShareExtAbility &extension, const uint8_t* data, size_t size)
{
    extension.GetFileTypes(FuzzUri(data, size), FuzzString(data, size));
}

static inline void OpenFileFuzzer(MediaDataShareExtAbility &extension, const uint8_t* data, size_t size)
{
    extension.OpenFile(FuzzUri(data, size), FuzzOpenMode(data, size));
}

static inline void OpenRawFileFuzzer(MediaDataShareExtAbility &extension, const uint8_t* data, size_t size)
{
    extension.OpenRawFile(FuzzUri(data, size), FuzzOpenMode(data, size));
}

static inline void InsertFuzzer(MediaDataShareExtAbility &extension, const uint8_t* data, size_t size)
{
    extension.Insert(FuzzUri(data, size), FuzzDataShareValuesBucket());
}

static inline void InsertExtFuzzer(MediaDataShareExtAbility &extension, const uint8_t* data, size_t size)
{
    string uri;
    extension.InsertExt(FuzzUri(data, size), FuzzDataShareValuesBucket(), uri);
}

static inline void UpdateFuzzer(MediaDataShareExtAbility &extension, const uint8_t* data, size_t size)
{
    extension.Update(FuzzUri(data, size), FuzzDataSharePredicates(data, size), FuzzDataShareValuesBucket());
}

static inline void DeleteFuzzer(MediaDataShareExtAbility &extension, const uint8_t* data, size_t size)
{
    extension.Delete(FuzzUri(data, size), FuzzDataSharePredicates(data, size));
}

static inline void QueryFuzzer(MediaDataShareExtAbility &extension, const uint8_t* data, size_t size)
{
    auto columns = FuzzVectorString(data, size);
    auto error = FuzzDataShareBusinessError(data, size);
    extension.Query(FuzzUri(data, size), FuzzDataSharePredicates(data, size), columns, error);
}

static inline void GetTypeFuzzer(MediaDataShareExtAbility &extension, const uint8_t* data, size_t size)
{
    extension.GetType(FuzzUri(data, size));
}

static inline void BatchInsertFuzzer(MediaDataShareExtAbility &extension, const uint8_t* data, size_t size)
{
    extension.BatchInsert(FuzzUri(data, size), FuzzVectorDataShareValuesBucket());
}

static inline void RegisterObserverFuzzer(MediaDataShareExtAbility &extension, const uint8_t* data, size_t size)
{
    sptr<AAFwk::IDataAbilityObserver> dataObserver;
    extension.RegisterObserver(FuzzUri(data, size), dataObserver);
}

static inline void UnregisterObserverFuzzer(MediaDataShareExtAbility &extension, const uint8_t* data, size_t size)
{
    sptr<AAFwk::IDataAbilityObserver> dataObserver;
    extension.UnregisterObserver(FuzzUri(data, size), dataObserver);
}

static inline void NotifyChangeFuzzer(MediaDataShareExtAbility &extension, const uint8_t* data, size_t size)
{
    extension.NotifyChange(FuzzUri(data, size));
}

static inline void NormalizeUriFuzzer(MediaDataShareExtAbility &extension, const uint8_t* data, size_t size)
{
    extension.NormalizeUri(FuzzUri(data, size));
}

static inline void DenormalizeUriFuzzer(MediaDataShareExtAbility &extension, const uint8_t* data, size_t size)
{
    extension.DenormalizeUri(FuzzUri(data, size));
}

static inline void StopFuzzer(MediaDataShareExtAbility &extension)
{
    extension.OnStop();
}

static int InitExtention(MediaDataShareExtAbility &extension)
{
    extension.InitPermissionHandler();
    auto stageContext = std::make_shared<AbilityRuntime::ContextImpl>();
    auto abilityContextImpl = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    abilityContextImpl->SetStageContext(stageContext);
    int32_t sceneCode = 0;
    return Media::MediaLibraryDataManager::GetInstance()->InitMediaLibraryMgr(abilityContextImpl, abilityContextImpl,
        sceneCode);
}

static inline MediaDataShareExtAbility Init()
{
    const std::unique_ptr<AbilityRuntime::Runtime> runtime;
    return {(*runtime)};
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    auto extension = OHOS::Init();
    OHOS::InitExtention(extension);
    OHOS::CreateFuzzer(extension);
    OHOS::GetFileTypesFuzzer(extension, data, size);
    OHOS::OpenFileFuzzer(extension, data, size);
    OHOS::OpenRawFileFuzzer(extension, data, size);
    OHOS::InsertFuzzer(extension, data, size);
    OHOS::InsertExtFuzzer(extension, data, size);
    OHOS::UpdateFuzzer(extension, data, size);
    OHOS::DeleteFuzzer(extension, data, size);
    OHOS::QueryFuzzer(extension, data, size);
    OHOS::GetTypeFuzzer(extension, data, size);
    OHOS::BatchInsertFuzzer(extension, data, size);
    OHOS::RegisterObserverFuzzer(extension, data, size);
    OHOS::UnregisterObserverFuzzer(extension, data, size);
    OHOS::NotifyChangeFuzzer(extension, data, size);
    OHOS::NormalizeUriFuzzer(extension, data, size);
    OHOS::DenormalizeUriFuzzer(extension, data, size);
    OHOS::StopFuzzer(extension);
    int sleepTime = 100;
    std::this_thread::sleep_for(std::chrono::microseconds(sleepTime));
    return 0;
}
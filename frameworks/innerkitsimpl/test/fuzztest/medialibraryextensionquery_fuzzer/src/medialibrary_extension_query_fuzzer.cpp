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
#include "medialibrary_extension_query_fuzzer.h"

#include <cstdint>
#include <memory>
#include <string>

#include "data_ability_observer_interface.h"
#include "datashare_business_error.h"
#include "datashare_helper.h"
#include "datashare_predicates.h"
#include "datashare_values_bucket.h"
#include "media_datashare_ext_ability.h"
#include "media_datashare_stub_impl.h"
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
    return Uri(FuzzString(data, size));
}

static inline DataSharePredicates FuzzDataSharePredicates(const uint8_t *data, size_t size)
{
    return DataSharePredicates(FuzzVectorOperationItem(data, size));
}

static inline DatashareBusinessError FuzzDataShareBusinessError(const uint8_t *data, size_t size)
{
    DatashareBusinessError error;
    error.SetCode(FuzzInt32(data, size));
    error.SetMessage(FuzzString(data, size));
    return error;
}

static inline void QueryFuzzer(MediaDataShareExtAbility &extension, const uint8_t* data, size_t size)
{
    auto columns = FuzzVectorString(data, size);
    auto error = FuzzDataShareBusinessError(data, size);
    extension.Query(FuzzUri(data, size), FuzzDataSharePredicates(data, size), columns, error);
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
    OHOS::QueryFuzzer(extension, data, size);
    return 0;
}

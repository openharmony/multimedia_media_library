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
#include "medialibrary_extension_batch_insert_fuzzer.h"

#include <cstdint>
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
static inline string FuzzString(const uint8_t *data, size_t size)
{
    return {reinterpret_cast<const char*>(data), size};
}

static inline Uri FuzzUri(const uint8_t *data, size_t size)
{
    return Uri(FuzzString(data, size));
}

static inline DataShareValuesBucket FuzzDataShareValuesBucket(const uint8_t *data, size_t size)
{
    return {};
}

static inline vector<DataShareValuesBucket> FuzzVectorDataShareValuesBucket(const uint8_t *data, size_t size)
{
    return {FuzzDataShareValuesBucket(data, size)};
}

static inline void BatchInsertFuzzer(MediaDataShareExtAbility &extension, const uint8_t* data, size_t size)
{
    extension.BatchInsert(FuzzUri(data, size), FuzzVectorDataShareValuesBucket(data, size));
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
    OHOS::BatchInsertFuzzer(extension, data, size);
    return 0;
}
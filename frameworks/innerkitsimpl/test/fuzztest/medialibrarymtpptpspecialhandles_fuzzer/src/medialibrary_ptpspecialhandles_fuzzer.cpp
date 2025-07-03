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
#include "medialibrary_ptpspecialhandles_fuzzer.h"

#include <cstdint>
#include <string>
#include <fstream>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "userfilemgr_uri.h"
#include "payload_data.h"
#include "close_session_data.h"
#include "media_log.h"

#define private public
#include "ptp_special_handles.h"
#undef private

namespace OHOS {
using namespace std;
using namespace Media;

FuzzedDataProvider *provider = nullptr;

static void PtpSpecialHandlesTest(const uint8_t* data, size_t size)
{
    auto specialInstance = PtpSpecialHandles::GetInstance();
    uint32_t deleteHandle = provider->ConsumeIntegral<u_int32_t>();
    uint32_t realHandle = provider->ConsumeIntegral<u_int32_t>();
    specialInstance->AddHandleToMap(deleteHandle, realHandle);
    deleteHandle = provider->ConsumeIntegral<u_int32_t>();
    realHandle = provider->ConsumeIntegral<u_int32_t>();
    specialInstance->AddHandleToMap(deleteHandle, realHandle);
    uint32_t key = provider->ConsumeIntegral<u_int32_t>();

    specialInstance->HandleConvertToAdded(key);
    specialInstance->FindRealHandle(key);
    specialInstance->HandleConvertToDeleted(key);
    specialInstance->FindDeletedHandle(key);
    specialInstance->ClearDeletedHandles();
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);
    OHOS::provider = &fdp;
    
    OHOS::PtpSpecialHandlesTest(data, size);
    return 0;
}

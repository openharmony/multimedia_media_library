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
#include "medialibrary_mtp_headerdata_fuzzer.h"

#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "userfilemgr_uri.h"
#include "payload_data.h"
#include "close_session_data.h"
#include "media_log.h"

#define private public
#include "header_data.h"
#undef private

namespace OHOS {
using namespace std;
using namespace Media;
static const int32_t NUM_BYTES = 1;
FuzzedDataProvider *provider = nullptr;

static void HeaderDataTest()
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is nullptr");
        return;
    }
    shared_ptr<HeaderData> headerData = make_shared<HeaderData>(context);

    vector<uint8_t> buffer = provider->ConsumeBytes<uint8_t>(NUM_BYTES);
    int32_t readSize = buffer.size();

    headerData->Parser(buffer, readSize);
    headerData->Maker(buffer);
    headerData->SetCode(provider->ConsumeIntegral<uint16_t>());
    headerData->SetContainerLength(provider->ConsumeIntegral<uint32_t>());
    headerData->SetContainerType(provider->ConsumeIntegral<uint16_t>());
    headerData->SetTransactionId(provider->ConsumeIntegral<uint32_t>());

    headerData->GetCode();
    headerData->GetContainerLength();
    headerData->GetContainerType();
    headerData->GetTransactionId();

    headerData->Reset();
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::provider = &fdp;
    if (data == nullptr) {
        return 0;
    }
    OHOS::HeaderDataTest();
    return 0;
}
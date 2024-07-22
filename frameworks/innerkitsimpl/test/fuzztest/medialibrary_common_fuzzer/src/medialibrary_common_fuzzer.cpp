/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "medialibrary_common_fuzzer.h"

#include <cstdint>
#include <string>

#include "media_log.h"
#include "media_scanner_manager.h"

namespace OHOS {
using namespace std;

static inline string FuzzString(const uint8_t *data, size_t size)
{
    return {reinterpret_cast<const char*>(data), size};
}

static inline void ScanTest(const uint8_t *data, size_t size)
{
    auto scannerManager = Media::MediaScannerManager::GetInstance();
    if (scannerManager != nullptr) {
        scannerManager->ScanDir(FuzzString(data, size), nullptr);
    }
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::ScanTest(data, size);
    return 0;
}
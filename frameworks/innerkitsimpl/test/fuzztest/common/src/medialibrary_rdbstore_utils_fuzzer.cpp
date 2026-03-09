/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "medialibrary_rdbstore_utils_fuzzer.h"

namespace OHOS {
namespace Media {

std::shared_ptr<MediaLibraryRdbStore> MediaLibraryRdbStoreUtilsTest::InitMediaLibraryRdbStore(
    const std::shared_ptr<OHOS::AbilityRuntime::Context> &context)
{
    int32_t ret = MediaLibraryUnistoreManager::GetInstance().Init(context);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, nullptr, "init MediaLibraryUnistoreManager failed");

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, nullptr, "rdbStore is nullptr");
    return rdbStore;
}
} // namespace Media
} // namespace OHOS

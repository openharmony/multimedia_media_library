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

#ifndef PHOTO_CUSTOM_RESTORE_OPERATION_FUZZER_H
#define PHOTO_CUSTOM_RESTORE_OPERATION_FUZZER_H

#define FUZZ_PROJECT_NAME "photocustomrestoreoperation_fuzzer"
#include <vector>
#define private public
#include "photo_custom_restore_operation.h"
#undef private

namespace OHOS {
namespace Media {

const std::vector<int> NOTIFY_TYPE_LIST = {
    NOTIFY_FIRST,
    NOTIFY_PROGRESS,
    NOTIFY_LAST,
    NOTIFY_CANCEL,
};

const std::vector<std::string> MIMETYPE_FUZZER_LISTS = {
    "image/jpeg",
    "image/heif",
};
} // namespace Media
} // namespace OHOS
#endif
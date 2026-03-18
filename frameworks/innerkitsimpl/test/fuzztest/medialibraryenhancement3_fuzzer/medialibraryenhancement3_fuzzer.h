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

#ifndef MEDIALIBRARY_ENHANCEMENT3_FUZZER_H
#define MEDIALIBRARY_ENHANCEMENT3_FUZZER_H

#define FUZZ_PROJECT_NAME "medialibraryenhancement3_fuzzer"

#include "userfilemgr_uri.h"
#include "medialibrary_type_const.h"
#include "cloud_enhancement_uri.h"

#include <string>
#include <vector>

namespace OHOS {
namespace Media {
const std::vector<std::string> ENHANCEMENT_FUZZER_URI_LISTS = {
    // PhotoAccessHelper cloud enhancement
    CONST_PAH_CLOUD_ENHANCEMENT_ADD,
    CONST_PAH_CLOUD_ENHANCEMENT_PRIORITIZE,
    CONST_PAH_CLOUD_ENHANCEMENT_CANCEL,
    CONST_PAH_CLOUD_ENHANCEMENT_CANCEL_ALL,
    CONST_PAH_CLOUD_ENHANCEMENT_SYNC,
    CONST_PAH_CLOUD_ENHANCEMENT_QUERY,
    CONST_PAH_CLOUD_ENHANCEMENT_GET_PAIR,
};
} // namespace Media
} // namespace OHOS
#endif
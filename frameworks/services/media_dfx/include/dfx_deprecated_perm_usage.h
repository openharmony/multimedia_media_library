/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_DFX_DEPRECATED_PERM_USAGE_H
#define OHOS_MEDIA_DFX_DEPRECATED_PERM_USAGE_H

#include <mutex>
#include <string>
#include <vector>

namespace OHOS {
namespace Media {

class DfxDeprecatedPermUsage {
public:
    static int32_t Record(const uint32_t object, const uint32_t type);
    static int32_t Statistics();

private:
    static int32_t ReportBatch(const uint32_t object, const uint32_t type, const std::vector<std::string> &bundleNames);
    static int32_t Report(const uint32_t object, const uint32_t type, const std::string &bundleNameList);

private:
    static std::mutex mutex_;
};
}  // namespace Media
}  // namespace OHOS

#endif  // OHOS_MEDIA_DFX_DEPRECATED_PERM_USAGE_H
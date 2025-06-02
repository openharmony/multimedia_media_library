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

#ifndef OHOS_MEDIA_CLOUD_REPORT_UTILS_H
#define OHOS_MEDIA_CLOUD_REPORT_UTILS_H

#include "cloud_file_fault_event.h"

namespace UtilCloud = OHOS::FileManagement::CloudFile;

#define UTIL_SYNC_FAULT_REPORT(...) \
    UtilCloud::CloudFileFaultEvent::CloudSyncFaultReport(__FUNCTION__, __LINE__, ##__VA_ARGS__)

namespace OHOS::Media::CloudSync {
struct ReportUtils {
    static std::string GetAnonyString(const std::string &value);
};

} // namespace OHOS::Media::CloudSync

#endif // OHOS_MEDIA_CLOUD_REPORT_UTILS_H
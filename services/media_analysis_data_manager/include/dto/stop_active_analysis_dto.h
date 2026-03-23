/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_ANALYSIS_DATA_STOP_ACTIVE_ANALYSIS_DTO_H
#define OHOS_MEDIA_ANALYSIS_DATA_STOP_ACTIVE_ANALYSIS_DTO_H

#include <string>
#include <vector>

#include "userfile_manager_types.h"

namespace OHOS::Media::AnalysisData {
class StopActiveAnalysisDto {
public:
    std::vector<int32_t> analysisTypes = { static_cast<int32_t>(ANALYSIS_SELECTED) };
    std::vector<std::string> fileIds;
    std::string param;
};
} // namespace OHOS::Media::AnalysisData

#endif // OHOS_MEDIA_ANALYSIS_DATA_STOP_ACTIVE_ANALYSIS_DTO_H

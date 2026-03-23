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

#ifndef OHOS_MEDIA_ACTIVE_ANALYSIS_MANAGER_H
#define OHOS_MEDIA_ACTIVE_ANALYSIS_MANAGER_H

#include <memory>

#include "start_active_analysis_dto.h"
#include "stop_active_analysis_dto.h"

namespace OHOS::Media::AnalysisData {
class ActiveAnalysisRemoteInvoker {
public:
    virtual ~ActiveAnalysisRemoteInvoker() = default;
    virtual sptr<IRemoteObject> GetSaRemote() const = 0;
    virtual int32_t StartActiveAnalysis(const StartActiveAnalysisDto &dto) const = 0;
    virtual int32_t StopActiveAnalysis(const StopActiveAnalysisDto &dto) const = 0;
};

class ActiveAnalysisManager {
public:
    static ActiveAnalysisManager &GetInstance();

    explicit ActiveAnalysisManager(std::shared_ptr<ActiveAnalysisRemoteInvoker> invoker);
    ActiveAnalysisManager(const ActiveAnalysisManager &) = delete;
    ActiveAnalysisManager &operator=(const ActiveAnalysisManager &) = delete;

    int32_t SubmitTask(const StartActiveAnalysisDto &dto, int32_t &resultCode, sptr<IRemoteObject> &saRemote);
    int32_t CancelTask(const StopActiveAnalysisDto &dto, int32_t &resultCode);

private:
    static bool AreSupportedTypes(const std::vector<int32_t> &analysisTypes);
    static bool IsSupportedType(int32_t analysisType);

    std::shared_ptr<ActiveAnalysisRemoteInvoker> invoker_;
};
} // namespace OHOS::Media::AnalysisData

#endif // OHOS_MEDIA_ACTIVE_ANALYSIS_MANAGER_H

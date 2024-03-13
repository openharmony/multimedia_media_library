/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_DFX_WORKER_H
#define OHOS_MEDIA_DFX_WORKER_H

#include <thread>

namespace OHOS {
namespace Media {
class DfxWorker {
public:
    DfxWorker();
    ~DfxWorker();
    static std::shared_ptr<DfxWorker> GetInstance();
    void Init();
    void End();

private:
    void InitCycleThread();
    bool PrepareVersionUpdate();

private:
    int64_t lastReportTime_;
    int32_t thumbnailVersion_;
    static std::shared_ptr<DfxWorker> dfxWorkerInstance_;
    std::thread cycleThread_;
    bool isEnd_;
    int32_t shortTime_;
    int32_t longTime_;
};
} // namespace Media
} // namespace OHOS

#endif  // OHOS_MEDIA_DFX_WORKER_H
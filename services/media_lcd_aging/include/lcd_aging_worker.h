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

#ifndef OHOS_MEDIA_LCD_AGING_WORKER_H
#define OHOS_MEDIA_LCD_AGING_WORKER_H

#include <atomic>
#include <mutex>
#include <thread>

namespace OHOS::Media {
class LcdAgingWorker {
public:
    static LcdAgingWorker& GetInstance();
    void StartLcdAgingWorker();
    bool IsRunning();

private:
    LcdAgingWorker() {}
    ~LcdAgingWorker();
    LcdAgingWorker(const LcdAgingWorker &worker) = delete;
    const LcdAgingWorker &operator=(const LcdAgingWorker &worker) = delete;

    void HandleLcdAgingTask();

private:
    std::atomic<bool> isThreadRunning_ {false};
    std::thread workerThread_;
};
}  // namespace OHOS::Media
#endif  // OHOS_MEDIA_LCD_AGING_WORKER_H
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

#ifndef FRAMEWORKS_SERVICES_CLOUD_SYNC_NOTIFY_HANDLE_INCLUDE_ANALYSYS_HANDLER_H
#define FRAMEWORKS_SERVICES_CLOUD_SYNC_NOTIFY_HANDLE_INCLUDE_ANALYSYS_HANDLER_H

#include <mutex>
#include <queue>
#include <functional>
#include "base_handler.h"
#include "medialibrary_period_worker.h"

namespace OHOS {
namespace Media {
class AnalysisHandler : public BaseHandler {
public:
    AnalysisHandler(std::function<void(bool)> refreshAlbums = nullptr) {}
    virtual ~AnalysisHandler();
    void Handle(const CloudSyncHandleData &handleData) override;
    void init() override;

    static std::queue<CloudSyncHandleData> taskQueue_;
    static std::mutex mtx_;
    static std::atomic<uint16_t> counts_;
    static void ProcessHandleData(PeriodTaskData *data);
private:
    void MergeTask(const CloudSyncHandleData &handleData);
};
} //namespace Media
} //namespace OHOS

#endif //FRAMEWORKS_SERVICES_CLOUD_SYNC_NOTIFY_HANDLE_INCLUDE_ANALYSYS_HANDLER_H

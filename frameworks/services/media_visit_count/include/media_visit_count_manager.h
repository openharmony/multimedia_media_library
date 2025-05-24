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
#ifndef MEDIA_VISIT_COUNT_MANAGER_H
#define MEDIA_VISIT_COUNT_MANAGER_H

#include <atomic>
#include <mutex>
#include <queue>

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
class MediaVisitCountManager {
public:
    enum class VisitCountType {
        PHOTO_FS = 0,
        PHOTO_LCD
    };

    EXPORT static void AddVisitCount(VisitCountType type, const std::string &fileId);
private:
    EXPORT MediaVisitCountManager() = delete;
    EXPORT virtual ~MediaVisitCountManager() = delete;
    EXPORT static void VisitCountThread();
    EXPORT static inline bool IsValidType(VisitCountType type)
    {
        return type == VisitCountType::PHOTO_FS || type == VisitCountType::PHOTO_LCD;
    }
private:
    static inline std::queue<std::pair<VisitCountType, std::string>> queue_;
    static inline std::atomic_bool isThreadRunning_ = false;
    static inline std::atomic_bool isTimerRefresh_ = false;
    static inline std::mutex mutex_;
    static inline std::condition_variable cv_;
};
} // namespace Media
} // namespace OHOS

#endif // MEDIA_VISIT_COUNT_MANAGER_H

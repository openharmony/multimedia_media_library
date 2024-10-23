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
#ifndef OHOS_MEDIALIBRARY_RESTORE_H
#define OHOS_MEDIALIBRARY_RESTORE_H

#include <mutex>
#include <string>
#include <memory>
#include "result_set.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
class MediaLibraryRestore {
public:
    MediaLibraryRestore() = default;
    virtual ~MediaLibraryRestore() = default;
    EXPORT static MediaLibraryRestore &GetInstance();

    EXPORT int32_t DetectHaMode(const std::string &dbPath);
    EXPORT void CheckRestore(const int32_t &errCode);
    EXPORT bool IsRestoring() const;
    EXPORT bool IsBackuping() const;
    EXPORT bool IsWaiting() const;
    EXPORT void DoRdbHAModeSwitch();
    EXPORT void InterruptRdbHAModeSwitch();
    EXPORT int32_t GetHaMode() const;
    EXPORT void ResetHaMode();
    EXPORT void CheckResultSet(const std::shared_ptr<NativeRdb::ResultSet> &resultSet);
private:
#ifdef CLOUD_SYNC_MANAGER
    void StopCloudSync();
#endif
    void SaveHAModeToPara();
    void SaveHAModeSwitchStatusToPara(const uint32_t &status);
    void ReadHAModeFromPara();
    bool isRestoring_{false};
    std::atomic<bool> isBackuping_{false};
    std::atomic<bool> isWaiting_{false};
    std::atomic<bool> isInterrupting_{false};
    int32_t haMode_{0};
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_RESTORE_H

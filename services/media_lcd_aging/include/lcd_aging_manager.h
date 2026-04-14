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

#ifndef OHOS_MEDIA_LCD_AGING_MANAGER_H
#define OHOS_MEDIA_LCD_AGING_MANAGER_H

#include <atomic>
#include <mutex>

#include "lcd_aging_dao.h"

namespace OHOS::Media {
class LcdAgingManager {
public:
    static LcdAgingManager& GetInstance();
    int32_t ReadyAgingLcd();
    int32_t BatchAgingLcdFileTask();
    void DelayLcdAgingTime();
    void ClearNotAgingFileIds();

private:
    LcdAgingManager() {}
    ~LcdAgingManager() {}
    LcdAgingManager(const LcdAgingManager &manager) = delete;
    const LcdAgingManager &operator=(const LcdAgingManager &manager) = delete;

    using BatchAgingLcdFileFunc = int32_t (LcdAgingManager::*)(const int32_t size, int64_t &agingSuccessSize);
    
    int32_t DoBatchAgingLcdFile(const std::vector<PhotosPo> &lcdAgingPoList, int64_t &agingSuccessSize);
    int32_t BatchAgingLcdFileTrashed(const int32_t size, int64_t &agingSuccessSize);
    int32_t BatchAgingLcdFileNotTrashed(const int32_t size, int64_t &agingSuccessSize);
    std::vector<std::string> GetFileIdFromAgingFiles(const std::vector<LcdAgingFileInfo> &agingFileInfos);
    void DeleteLocalLcdFiles(const std::vector<LcdAgingFileInfo> &agingFileInfos,
        const std::vector<std::string> &failCloudIds, std::vector<std::string> &failFileIds);
    int32_t DeleteLocalFile(const std::string &localPath);
    int64_t GetLastLcdAgingEndTime();
    void UpdateLastLcdAgingEndTime(const int64_t lastLcdAgingEndTime);
    std::vector<LcdAgingFileInfo> GetLcdAgingFileInfo(const std::vector<PhotosPo> &photos);
    bool CheckLocalLcd(LcdAgingFileInfo &agingFileInfo);
    int32_t RegenerateAstcWithLocal(const LcdAgingFileInfo &agingFileInfo);
    int32_t GetNeedAgingLcdSize(int64_t &taskSize);
    int32_t FinishAgingTask();
    bool IsLcdAgingStatusOn();

private:
    LcdAgingDao lcdAgingDao_;
    std::mutex lcdOperationMutex_;
    std::atomic<bool> isCompletePull_ {true};
    std::atomic<bool> isInAgingPeriod_ {false};
    std::vector<std::string> notAgingFileIds_;
    int64_t hasAgingLcdNumber_ {0};
};
}  // namespace OHOS::Media
#endif  // OHOS_MEDIA_LCD_AGING_MANAGER_H
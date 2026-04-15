/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_BACKGROUND_MEDIA_LCD_SIZE_TASK_H
#define OHOS_MEDIA_BACKGROUND_MEDIA_LCD_SIZE_TASK_H

#include <cstdint>
#include <vector>
#include <string>

#include "i_media_background_task.h"

namespace OHOS::Media::Background {
#define EXPORT __attribute__ ((visibility ("default")))

struct LcdAssetInfo {
    int32_t fileId;
    int32_t photoHeight;
    int32_t photoWidth;
    std::string lcdSize;
    int32_t lcdWidth;
    int32_t lcdHeight;
};

class EXPORT MediaLcdSizeTask : public IMediaBackGroundTask {
public:
    MediaLcdSizeTask() = default;
    virtual ~MediaLcdSizeTask() = default;

public:
    bool Accept() override;
    void Execute() override;

private:
    void SetCursorStatus(int32_t cursor);
    int32_t GetCursorStatus();
    int32_t QueryLcdAssets(const int32_t startFileId, std::vector<LcdAssetInfo> &lcdAssetInfos);
    bool ParseLcdSize(const std::string &lcdSize, int32_t &lcdWidth, int32_t &lcdHeight);
    bool IsSpecialAsset(LcdAssetInfo &assetInfo);
    int32_t UpdateDirtyStatus(const std::vector<std::string> &fileIds);
    void HandleLcdSize();
};
} // namespace OHOS::Media::Background
#endif // OHOS_MEDIA_BACKGROUND_MEDIA_LCD_SIZE_TASK_H

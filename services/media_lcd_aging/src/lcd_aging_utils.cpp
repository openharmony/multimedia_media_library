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
#define MLOG_TAG "Lcd_Aging"

#include "lcd_aging_utils.h"

#include <cinttypes>
#include <map>

#include "exif_rotate_utils.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "userfile_manager_types.h"

namespace OHOS::Media {
constexpr double LCD_SCALE_FACTOR = 0.8;
constexpr int64_t GB_SIZE = 1000 * 1000 * 1000;
constexpr int64_t TEN_THOUSAND = 10000;
constexpr int64_t TWENTY_THOUSAND = 20000;
const std::string DENTRY_INFO_LCD_EX = "THM_EX/LCD";
const std::string DENTRY_INFO_LCD = "LCD";
const std::string FILE_NAME_LCD = "LCD.jpg";
const int64_t THUMB_DENTRY_SIZE = 2 * 1024 * 1024;

int64_t LcdAgingUtils::maxLcdNumber_ = -1;
int64_t LcdAgingUtils::scaleLcdNumber_ = -1;

// key = storage size, value = max lcd number
// storage size <= 128GB, max lcd number = 2 * 10000
// storage size >= 256GB, max lcd number = 5 * 10000
// storage size >= 512GB, max lcd number = 8 * 10000
// storage size >= 1024GB, max lcd number = 15 * 10000
const std::map<int64_t, int64_t> LcdMaxNumberMap = {
    { 256 * GB_SIZE, 5 * TEN_THOUSAND },
    { 512 * GB_SIZE, 8 * TEN_THOUSAND },
    { 1024 * GB_SIZE, 15 * TEN_THOUSAND },
};

int32_t LcdAgingUtils::GetMaxThresholdOfLcd(int64_t &lcdNumber)
{
    if (maxLcdNumber_ > 0) {
        lcdNumber = maxLcdNumber_;
        return E_OK;
    }

    int64_t diskSize = MediaFileUtils::GetTotalSize();
    CHECK_AND_EXECUTE(diskSize > 0, diskSize = MediaFileUtils::GetTotalSize());
    CHECK_AND_RETURN_RET_LOG(diskSize > 0, E_ERR, "Failed to GetTotalSize, diskSize:%{public}" PRId64, diskSize);

    if (diskSize < LcdMaxNumberMap.begin()->first) {
        maxLcdNumber_ = TWENTY_THOUSAND;
        lcdNumber = maxLcdNumber_;
        return E_OK;
    }

    for (auto it = LcdMaxNumberMap.rbegin(); it != LcdMaxNumberMap.rend(); it++) {
        CHECK_AND_CONTINUE(diskSize >= it->first);
        maxLcdNumber_ = it->second;
        break;
    }
    lcdNumber = maxLcdNumber_;
    return E_OK;
}

int32_t LcdAgingUtils::GetScaleThresholdOfLcd(int64_t &lcdNumber)
{
    if (scaleLcdNumber_ > 0) {
        lcdNumber = scaleLcdNumber_;
        return E_OK;
    }

    int64_t maxLcdNumber = -1;
    int32_t ret = GetMaxThresholdOfLcd(maxLcdNumber);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, E_ERR, "Failed to GetMaxThresholdOfLcd");

    scaleLcdNumber_ = static_cast<int64_t>(maxLcdNumber * LCD_SCALE_FACTOR);
    lcdNumber = scaleLcdNumber_;
    return E_OK;
}

std::vector<DentryFileInfo> LcdAgingUtils::ConvertAgingFileToDentryFile(
    const std::vector<LcdAgingFileInfo> &agingFileInfos)
{
    std::vector<DentryFileInfo> dentryFileInfos;
    for (auto &agingFileInfo : agingFileInfos) {
        DentryFileInfo dentryFileInfo;
        dentryFileInfo.cloudId = agingFileInfo.cloudId;
        dentryFileInfo.modifiedTime = agingFileInfo.dateModified;
        dentryFileInfo.path = agingFileInfo.path;
        dentryFileInfo.size = THUMB_DENTRY_SIZE;
        dentryFileInfo.fileType = agingFileInfo.hasExThumbnail ? DENTRY_INFO_LCD_EX : DENTRY_INFO_LCD;

        dentryFileInfo.fileName = FILE_NAME_LCD;
        dentryFileInfos.emplace_back(dentryFileInfo);
    }
    return dentryFileInfos;
}

bool LcdAgingUtils::HasExThumbnail(const LcdAgingFileInfo &agingFileInfo)
{
    return (agingFileInfo.mediaType == MediaType::MEDIA_TYPE_IMAGE) &&
        (agingFileInfo.orientation != 0 || agingFileInfo.exifRotate > static_cast<int32_t>(ExifRotateType::TOP_LEFT));
}
}  // namespace OHOS::Media
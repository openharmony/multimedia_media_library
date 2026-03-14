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

#ifndef OHOS_MEDIA_LCD_AGING_DAO_H
#define OHOS_MEDIA_LCD_AGING_DAO_H

#include <string>
#include <vector>

namespace OHOS::Media {

class LcdAgingDao {
public:
    int32_t GetCurrentNumberOfLcd(int64_t &lcdNumber);

private:
    const std::string SQL_GET_TOTAL_NUMBER_OF_LCD = "\
        SELECT count(1) AS count \
        FROM Photos \
        WHERE \
            clean_flag = 0 AND ( \
            position IN (1, 3) OR \
            (position = 2 AND (thumb_status & 1) = 0));";
};
}  // namespace OHOS::Media
#endif  // OHOS_MEDIA_LCD_AGING_DAO_H
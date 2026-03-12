/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "media_library_lcd_aging_test.h"

#include "lcd_aging_utils.h"
#include "media_log.h"
#include "medialibrary_errno.h"

using namespace std;
using namespace OHOS;
using namespace::testing::ext;

namespace OHOS {
namespace Media {

void MediaLibraryLcdAgingTest::SetUpTestCase(void) {}

void MediaLibraryLcdAgingTest::TearDownTestCase(void) {}

void MediaLibraryLcdAgingTest::SetUp() {}

void MediaLibraryLcdAgingTest::TearDown(void) {}

HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_GetMaxThresholdOfLcd_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("Begin lcd_aging_GetMaxThresholdOfLcd_test_001");
    int64_t lcdNumber = 0;
    int32_t ret = LcdAgingUtils().GetMaxThresholdOfLcd(lcdNumber);
    EXPECT_EQ(ret, E_OK);
    EXPECT_GE(lcdNumber, 20000);
}


HWTEST_F(MediaLibraryLcdAgingTest, lcd_aging_GetScaleThresholdOfLcd_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("Begin lcd_aging_GetScaleThresholdOfLcd_test_001");
    int64_t lcdNumber = 0;
    int32_t ret = LcdAgingUtils().GetScaleThresholdOfLcd(lcdNumber);
    EXPECT_EQ(ret, E_OK);
    EXPECT_GE(lcdNumber, 16000);
}
} // namespace Media
} // namespace OHOS
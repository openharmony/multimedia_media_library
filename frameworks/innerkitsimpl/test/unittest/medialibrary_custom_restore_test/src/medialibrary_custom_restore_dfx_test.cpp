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

#define private public
#define MLOG_TAG "CustomRestoreCallbackUnitTest"

#include <gtest/gtest.h>

#include "dfx_reporter.h"
#include "media_log.h"
#include "medialibrary_errno.h"

using namespace testing;
using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
class MediaLibraryCustomRestoreDfxTest : public testing::Test {
public:
    // input testsuit setup step，setup invoked before all testcases
    static void SetUpTestCase(void);
    // input testsuit teardown step，teardown invoked after all testcases
    static void TearDownTestCase(void);
    // input testcase setup step，setup invoked before each testcases
    void SetUp();
    // input testcase teardown step，teardown invoked after each testcases
    void TearDown();
};

void MediaLibraryCustomRestoreDfxTest::SetUpTestCase(void) {}

void MediaLibraryCustomRestoreDfxTest::TearDownTestCase(void) {}

void MediaLibraryCustomRestoreDfxTest::SetUp(void) {}

void MediaLibraryCustomRestoreDfxTest::TearDown(void) {}

HWTEST_F(MediaLibraryCustomRestoreDfxTest, Custom_Restore_DFX_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Custom_Restore_DFX_Test_001 Start");
    CustomRestoreDfxDataPoint dfxDataPoint;
    dfxDataPoint.customRestorePackageName = "customRestorePackageName";
    dfxDataPoint.albumLPath = "albumLPath";
    dfxDataPoint.keyPath = "keyPath";
    dfxDataPoint.totalNum = 11;
    dfxDataPoint.successNum = 12;
    dfxDataPoint.failedNum = 13;
    dfxDataPoint.sameNum = 14;
    dfxDataPoint.cancelNum = 16;
    dfxDataPoint.totalTime = 102221;
    EXPECT_EQ(DfxReporter::ReportCustomRestoreFusion(dfxDataPoint), E_OK);
    MEDIA_INFO_LOG("Custom_Restore_DFX_Test_001 End");
}
}
}
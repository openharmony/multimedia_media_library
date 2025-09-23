/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "medialibrary_dfx_test.h"

#include <string>
#include <unordered_set>

#include "dfx_cloud_manager.h"
#include "dfx_collector.h"
#include "dfx_const.h"
#include "dfx_database_utils.h"
#include "dfx_manager.h"
#include "dfx_reporter.h"
#include "dfx_utils.h"
#include "hisysevent.h"
#include "medialibrary_astc_stat.h"
#include "medialibrary_errno.h"
#include "medialibrary_inotify.h"
#include "medialibrary_rdbstore.h"
#include "media_file_utils.h"
#include "photo_album_column.h"
#include "preferences.h"
#include "preferences_helper.h"
#include "parameters.h"

using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {

class MediaLibraryDfxPatchTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void MediaLibraryDfxPatchTest::SetUpTestCase(void)
{
    DfxManager::GetInstance();
}
void MediaLibraryDfxPatchTest::TearDownTestCase(void) {}

// SetUp:Execute before each test case
void MediaLibraryDfxPatchTest::SetUp()
{
    DfxManager::GetInstance()->isInitSuccess_ = true;
}

void MediaLibraryDfxPatchTest::TearDown(void) {}

HWTEST_F(MediaLibraryDfxPatchTest, ReportSyncStat_001, TestSize.Level0)
{
    DfxReporter dfxReporter;
    std::string taskId = "0000110";
    CloudSyncInfo cloudSyncInfo{};
    CloudSyncStat cloudSyncStat{};
    std::string syncInfo = "syncInfoDfx";
    int32_t southDeviceType = 0;
    int32_t ret = dfxReporter.ReportSyncStat(taskId, cloudSyncInfo, cloudSyncStat, syncInfo, southDeviceType);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaLibraryDfxPatchTest, ReportSyncFault_001, TestSize.Level0)
{
    DfxReporter dfxReporter;
    std::string taskId = "0000110";
    std::string position = "2";
    SyncFaultEvent event;
    int32_t southDeviceType = 0;
    int32_t ret = dfxReporter.ReportSyncFault(taskId, position, event, southDeviceType);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaLibraryDfxPatchTest, ReportUpgradeFault_001, TestSize.Level0)
{
    DfxReporter dfxReporter;
    UpgradeExceptionInfo reportData;
    reportData.srcVersion = 501;
    reportData.dstVersion = 502;
    reportData.isSync = false;
    reportData.exceptionVersions = "0,1,2,3";
    reportData.duration = 3000;
    int32_t ret = dfxReporter.ReportUpgradeFault(reportData);
    EXPECT_EQ(ret, E_OK);
}
} // namespace Media
} // namespace OHOS
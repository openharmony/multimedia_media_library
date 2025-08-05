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

#define MLOG_TAG "DfxDeprecatedPermUsageTest"

#include "dfx_deprecated_perm_usage_test.h"

#include <thread>

#include "dfx_deprecated_perm_usage.h"
#include "media_file_utils.h"
#include "hisysevent.h"
#include "medialibrary_astc_stat.h"
#include "medialibrary_business_code.h"
#include "medialibrary_errno.h"
#include "medialibrary_inotify.h"
#include "medialibrary_operation.h"
#include "media_file_utils.h"
#include "preferences.h"
#include "preferences_helper.h"
#include "parameters.h"

namespace OHOS::Media {
using namespace std;
using namespace testing::ext;

static constexpr int32_t SLEEP_ONE_SECONDS = 1;

void DfxDeprecatedPermUsageTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
}

void DfxDeprecatedPermUsageTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase");
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_ONE_SECONDS));
}

void DfxDeprecatedPermUsageTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void DfxDeprecatedPermUsageTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

HWTEST_F(DfxDeprecatedPermUsageTest, DfxDeprecatedPermUsage_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start DfxDeprecatedPermUsage_Test_001");

    uint32_t code = static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_GET_ASSETS);
    int32_t ret = DfxDeprecatedPermUsage::Record(code, 0);
    EXPECT_EQ(ret, E_OK);

    code = static_cast<uint32_t>(MediaLibraryBusinessCode::INNER_QUERY_PHOTO_STATUS);
    ret = DfxDeprecatedPermUsage::Record(code, 0);
    EXPECT_EQ(ret, E_OK);

    code = static_cast<uint32_t>(MediaLibraryBusinessCode::ALBUM_GET_ASSETS);
    ret = DfxDeprecatedPermUsage::Record(code, 0);
    EXPECT_EQ(ret, E_OK);

    uint32_t object = static_cast<uint32_t>(OperationObject::FILESYSTEM_PHOTO);
    uint32_t type = static_cast<uint32_t>(OperationType::QUERY);
    ret = DfxDeprecatedPermUsage::Record(object, type);
    EXPECT_EQ(ret, E_OK);

    ret = DfxDeprecatedPermUsage::Statistics();
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("End DfxDeprecatedPermUsage_Test_001");
}
}  // namespace OHOS::Media
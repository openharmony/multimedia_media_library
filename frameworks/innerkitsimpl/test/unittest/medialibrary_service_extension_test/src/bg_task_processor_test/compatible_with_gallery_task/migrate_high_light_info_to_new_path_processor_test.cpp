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

#include "bg_task_processor_test.h"

#include "media_log.h"
#include "medialibrary_db_const_sqls.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_type_const.h"
#include "media_file_utils.h"
#include "photo_file_utils.h"
#include "values_bucket.h"
#include "rdb_utils.h"

#define private public
#include "migrate_high_light_info_to_new_path_processor.h"
#undef private

using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {
const std::string OLD_DIR = "/storage/cloud/files/.thumbs/highlight";
const std::string NEW_DIR = "/storage/cloud/files/highlight";

const std::string OLD_PATH = "/storage/cloud/files/.thumbs/highlight/test.jpg";
const std::string NEW_PATH = "/storage/cloud/files/highlight/test.jpg";

/**
 * @tc.name: DoMigrateHighLight_test_001
 * @tc.desc: OLD_DIR 和 NEW_DIR, 均不存在
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, DoMigrateHighLight_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("DoMigrateHighLight_test_001 start");
    EXPECT_EQ(MediaFileUtils::IsDirectory(OLD_DIR), false);

    auto processor = MigrateHighLightInfoToNewPathProcessor();
    processor.DoMigrateHighLight();

    EXPECT_EQ(MediaFileUtils::IsDirectory(OLD_DIR), false);
    EXPECT_EQ(MediaFileUtils::IsDirectory(NEW_DIR), false);
    MEDIA_INFO_LOG("DoMigrateHighLight_test_001 end");
}

/**
 * @tc.name: DoMigrateHighLight_test_002
 * @tc.desc: OLD_DIR 目录存在, 但是没有文件, 则会清除 OLD_DIR 目录
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, DoMigrateHighLight_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("DoMigrateHighLight_test_002 start");
    EXPECT_EQ(MediaFileUtils::IsDirectory(OLD_DIR), false);
    EXPECT_EQ(MediaFileUtils::CreateDirectory(OLD_DIR), true);
    EXPECT_EQ(MediaFileUtils::IsDirectory(OLD_DIR), true);

    auto processor = MigrateHighLightInfoToNewPathProcessor();
    processor.DoMigrateHighLight();

    EXPECT_EQ(MediaFileUtils::IsDirectory(OLD_DIR), false);
    MEDIA_INFO_LOG("DoMigrateHighLight_test_002 end");
}

/**
 * @tc.name: DoMigrateHighLight_test_003
 * @tc.desc: OLD_DIR 目录存在且有文件, NEW_DIR 不存在, 则会把对应文件存放到 NEW_DIR 目录中, 并清除 OLD_DIR 目录
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, DoMigrateHighLight_test_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("DoMigrateHighLight_test_003 start");
    // 创建 OLD_DIR 目录
    EXPECT_EQ(MediaFileUtils::IsDirectory(OLD_DIR), false);
    EXPECT_EQ(MediaFileUtils::CreateDirectory(OLD_DIR), true);
    EXPECT_EQ(MediaFileUtils::IsDirectory(OLD_DIR), true);

    // 创建 OLD_PATH 文件
    EXPECT_EQ(MediaFileUtils::CreateFile(OLD_PATH), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(OLD_PATH), true);

    // NEW_DIR 不存在
    EXPECT_EQ(MediaFileUtils::IsDirectory(NEW_DIR), false);

    auto processor = MigrateHighLightInfoToNewPathProcessor();
    processor.DoMigrateHighLight();

    EXPECT_EQ(MediaFileUtils::IsFileExists(OLD_PATH), false);
    EXPECT_EQ(MediaFileUtils::IsDirectory(OLD_DIR), false);
    EXPECT_EQ(MediaFileUtils::IsDirectory(NEW_DIR), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(NEW_PATH), true);
    MEDIA_INFO_LOG("DoMigrateHighLight_test_003 end");
}

/**
 * @tc.name: DoMigrateHighLight_test_004
 * @tc.desc: OLD_DIR 目录存在且有文件, NEW_DIR 存在, 则会把对应文件存放到 NEW_DIR 目录中, 并清除 OLD_DIR 目录
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, DoMigrateHighLight_test_004, TestSize.Level1)
{
    MEDIA_INFO_LOG("DoMigrateHighLight_test_004 start");
    // 创建 OLD_DIR 目录
    EXPECT_EQ(MediaFileUtils::IsDirectory(OLD_DIR), false);
    EXPECT_EQ(MediaFileUtils::CreateDirectory(OLD_DIR), true);
    EXPECT_EQ(MediaFileUtils::IsDirectory(OLD_DIR), true);

    // 创建 OLD_PATH 文件
    EXPECT_EQ(MediaFileUtils::CreateFile(OLD_PATH), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(OLD_PATH), true);

    // NEW_DIR 不存在
    EXPECT_EQ(MediaFileUtils::IsDirectory(NEW_DIR), false);
    EXPECT_EQ(MediaFileUtils::CreateDirectory(NEW_DIR), true);
    EXPECT_EQ(MediaFileUtils::IsDirectory(OLD_DIR), true);

    auto processor = MigrateHighLightInfoToNewPathProcessor();
    processor.DoMigrateHighLight();

    EXPECT_EQ(MediaFileUtils::IsFileExists(OLD_PATH), false);
    EXPECT_EQ(MediaFileUtils::IsDirectory(OLD_DIR), false);
    EXPECT_EQ(MediaFileUtils::IsDirectory(NEW_DIR), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(NEW_PATH), true);
    MEDIA_INFO_LOG("DoMigrateHighLight_test_004 end");
}
} // namespace Media
} // namespace OHOS

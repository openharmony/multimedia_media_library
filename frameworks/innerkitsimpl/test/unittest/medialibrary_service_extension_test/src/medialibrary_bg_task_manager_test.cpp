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
#include "medialibrary_bg_task_manager.h"
#undef private

using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {

HWTEST_F(MediaLibraryBgTaskProcessorTest, DownloadOriginCloudFilesForLogin_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("DownloadOriginCloudFilesForLogin_test_001 start");
    auto mediaLibraryBgTaskManager = MediaLibraryBgTaskManager();
    int32_t ret = mediaLibraryBgTaskManager.Start(DELETE_TEMPORARY_PHOTOS, "test");
    EXPECT_EQ(ret, E_OK);
    ret = mediaLibraryBgTaskManager.Start("DoUpdateBurstFromGalleryTest", "test");
    EXPECT_EQ(ret, E_ERR);
    MEDIA_INFO_LOG("DownloadOriginCloudFilesForLogin_test_001 end");
}

} // namespace Media
} // namespace OHOS

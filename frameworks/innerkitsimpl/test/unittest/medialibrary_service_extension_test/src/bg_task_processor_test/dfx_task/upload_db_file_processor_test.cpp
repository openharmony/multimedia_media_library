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

#include <sys/stat.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "medialibrary_errno.h"
#include "media_log.h"
#include "medialibrary_unistore_manager.h"
#include "media_file_utils.h"
#define private public
#include "upload_db_file_processor.h"
#undef private

using namespace std;
using namespace testing::ext;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
const std::string DEST_PATH = "/data/storage/el2/log/logpack";
const std::string DEST_DB_PATH = "/data/storage/el2/log/logpack/media_library.db";
const std::string ZIP_DEST_DB_PATH = "/data/storage/el2/log/logpack/media_library.db.zip";
const int32_t SMALL_FILE_SIZE_MB = 100;
const int32_t LARGE_FILE_SIZE_MB = 400;

HWTEST_F(MediaLibraryBgTaskProcessorTest, UploadDBFile_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("UploadDBFile_test_001 start");
    system("rm -rf /data/storage/el2/log/logpack/*");
    auto processor = UploadDbFileProcessor();
    processor.UploadDBFile();
    EXPECT_EQ(MediaFileUtils::IsDirEmpty(DEST_PATH), false);
    MEDIA_INFO_LOG("UploadDBFile_test_001 end");
}

HWTEST_F(MediaLibraryBgTaskProcessorTest, UploadDBFileInner_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("UploadDBFile_test_001 start");
    system("rm -rf /data/storage/el2/log/logpack/*");
    auto processor = UploadDbFileProcessor();
    processor.UploadDBFileInner(SMALL_FILE_SIZE_MB);
    EXPECT_EQ(MediaFileUtils::IsFileExists(DEST_DB_PATH), true);
    processor.UploadDBFileInner(LARGE_FILE_SIZE_MB);
    EXPECT_EQ(MediaFileUtils::IsFileExists(ZIP_DEST_DB_PATH), true);
    MEDIA_INFO_LOG("UploadDBFile_test_001 end");
}

} // namespace Media
} // namespace OHOS

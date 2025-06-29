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
const std::string TEST_DB_DIR = "/data/storage/el2/database/rdb";
const std::string TEST_DB_FILE_PATH = TEST_DB_DIR + "/media_library.db";
const std::string TEST_DBSHM_FILE_PATH = TEST_DB_DIR + "/media_library.db-shm";
const std::string TEST_DBWAL_FILE_PATH = TEST_DB_DIR + "/media_library.db-wal";

const std::string DB_DIR = "/data/medialibrary/database/rdb";
const std::string DB_FILE_PATH = DB_DIR + "/media_library.db";
const std::string DBSHM_FILE_PATH = DB_DIR + "/media_library.db-shm";
const std::string DBWAL_FILE_PATH = DB_DIR + "/media_library.db-wal";

const std::string DEST_PATH = "/data/storage/el2/log/logpack";
const std::string DEST_DB_PATH = "/data/storage/el2/log/logpack/media_library.db";
const std::string ZIP_DEST_DB_PATH = "/data/storage/el2/log/logpack/media_library.db.zip";

const off_t MAX_FILE_SIZE_MEGABTYE_10G = 10240ULL * 1024ULL * 1024ULL;
const off_t FILE_SIZE_MEGABTYE_OVER_10G = 10241ULL * 1024ULL * 1024ULL; // 超过 10G

const int32_t SMALL_FILE_SIZE_MB = 100;
const int32_t LARGE_FILE_SIZE_MB = 400;

bool ModifyFileSize(const std::string &filePath, off_t newSize)
{
    int32_t fd = open(filePath.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        MEDIA_ERR_LOG("Failed to open file");
        return false;
    }

    if (ftruncate(fd, newSize) == -1) {
        MEDIA_ERR_LOG("Failed to truncate file");
        close(fd);
        return false;
    }

    // 关闭文件描述符
    close(fd);
    return true;
}

/**
 * @tc.name: UploadDBFile_test_001
 * @tc.desc: 不会上传超过10GB的数据库文件
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, UploadDBFile_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("UploadDBFile_test_001 start");
    EXPECT_EQ(MediaFileUtils::IsDirectory(TEST_DB_DIR), true);
    EXPECT_EQ(MediaFileUtils::IsDirectory(DB_DIR), true);

    EXPECT_EQ(MediaFileUtils::IsFileExists(TEST_DB_FILE_PATH), true);
    EXPECT_EQ(MediaFileUtils::IsFileExists(DB_FILE_PATH), false);
    bool ret = MediaFileUtils::CopyFileUtil(TEST_DB_FILE_PATH, DB_FILE_PATH);
    EXPECT_EQ(MediaFileUtils::IsFileExists(DB_FILE_PATH), true);

    ret = ModifyFileSize(DB_FILE_PATH, FILE_SIZE_MEGABTYE_OVER_10G);
    EXPECT_EQ(ret, true);

    size_t dbFileSize = 0;
    ret = MediaFileUtils::GetFileSize(DB_FILE_PATH, dbFileSize);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(dbFileSize, FILE_SIZE_MEGABTYE_OVER_10G);
    
    auto processor = UploadDbFileProcessor();
    processor.UploadDBFile();
    EXPECT_EQ(MediaFileUtils::IsFileExists(DEST_DB_PATH), false);
    EXPECT_EQ(MediaFileUtils::IsFileExists(ZIP_DEST_DB_PATH), false);
    MEDIA_INFO_LOG("UploadDBFile_test_001 end");
}
} // namespace Media
} // namespace OHOS

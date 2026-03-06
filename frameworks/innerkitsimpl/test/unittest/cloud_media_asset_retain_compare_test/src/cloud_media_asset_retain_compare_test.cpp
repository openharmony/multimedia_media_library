/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#define MLOG_TAG "CloudMediaAssetRetainCompareTest"

#include "cloud_media_asset_retain_compare_test.h"

#include <chrono>
#include <sstream>
#include <thread>
#include <vector>

#include "media_column.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_mock_tocken.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_unittest_utils.h"
#include "cloud_media_sync_const.h"

#define private public
#define protected public
#include "cloud_media_asset_retain_compare_dao.h"
#undef private
#undef protected


using namespace std;
using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::Media::CloudSync;

namespace OHOS {
namespace Media {
static shared_ptr<MediaLibraryRdbStore> g_rdbStore;
static uint64_t g_shellToken = 0;
static MediaLibraryMockHapToken* mockToken = nullptr;

void CleanTestTables()
{
    vector<string> dropTableList = {
        "PhotosAlbumBackupForSaveAnalysisData",
        "Photos"
    };
    for (auto &dropTable : dropTableList) {
        string dropSql = "DROP TABLE IF EXISTS " + dropTable + ";";
        int32_t ret = g_rdbStore->ExecuteSql(dropSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Drop %{public}s table failed", dropTable.c_str());
        }
    }
}

void SetTables()
{
    string createPhotosTable = R"(
        CREATE TABLE IF NOT EXISTS Photos (
            file_id INTEGER PRIMARY KEY AUTOINCREMENT,
            data TEXT,
            display_name TEXT,
            size INTEGER,
            media_type INTEGER,
            owner_album_id INTEGER,
            orientation INTEGER,
            clean_flag INTEGER DEFAULT 0,
            position INTEGER DEFAULT 0,
            real_lcd_visit_time INTEGER DEFAULT 0,
            source_path TEXT,
            hidden INTEGER DEFAULT 0,
            date_trashed INTEGER DEFAULT 0
        );
    )";

    string createBackupAlbumTable = R"(
        CREATE TABLE IF NOT EXISTS PhotosAlbumBackupForSaveAnalysisData (
            album_id INTEGER PRIMARY KEY,
            lpath TEXT
        );
    )";

    vector<string> createTableSqlList = {
        createPhotosTable,
        createBackupAlbumTable
    };
    for (auto &createTableSql : createTableSqlList) {
        int32_t ret = g_rdbStore->ExecuteSql(createTableSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Execute sql failed");
        }
    }
}

void ClearAndRestart()
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MediaLibraryUnitTestUtils::Init();
    }
    CleanTestTables();
    SetTables();
}

void ExecSqlOrAssert(const std::string &sql)
{
    ASSERT_NE(g_rdbStore, nullptr);
    int32_t ret = g_rdbStore->ExecuteSql(sql);
    ASSERT_EQ(ret, NativeRdb::E_OK) << sql;
}

void InsertBackupAlbum(int32_t albumId, const std::string &lpath)
{
    std::stringstream ss;
    ss << "INSERT INTO PhotosAlbumBackupForSaveAnalysisData (album_id, lpath) VALUES ("
       << albumId << ", '" << lpath << "');";
    ExecSqlOrAssert(ss.str());
}

struct PhotoRowOptions {
    bool hasOwnerAlbumId {false};
    int32_t ownerAlbumId {0};
    int32_t orientation {0};
    int32_t cleanFlag {0};
    int32_t position {0};
    int64_t realLcdVisitTime {0};
    std::string dataPath;
    std::string sourcePath;
    int32_t hidden {0};
    int64_t dateTrashed {0};
};

void InsertPhotoRow(int32_t fileId, const std::string &displayName, int64_t size, int32_t mediaType,
    const PhotoRowOptions &options = PhotoRowOptions())
{
    std::string finalDataPath = options.dataPath.empty() ? ("/data/" + displayName) : options.dataPath;
    std::string ownerAlbumValue = options.hasOwnerAlbumId ? std::to_string(options.ownerAlbumId) : "NULL";
    std::stringstream ss;
    ss << "INSERT INTO Photos (file_id, data, display_name, size, media_type, owner_album_id, orientation, "
          "clean_flag, position, real_lcd_visit_time, source_path, hidden, date_trashed) VALUES ("
       << fileId << ", '" << finalDataPath << "', '" << displayName << "', " << size << ", " << mediaType << ", "
       << ownerAlbumValue << ", " << options.orientation << ", " << options.cleanFlag << ", " << options.position
       << ", " << options.realLcdVisitTime << ", '" << options.sourcePath << "', " << options.hidden << ", "
       << options.dateTrashed << ");";
    ExecSqlOrAssert(ss.str());
}

CloudMediaPullDataDto BuildPullData(const std::string &cloudId, const std::string &fileName, int64_t fileSize,
    int32_t fileType)
{
    CloudMediaPullDataDto pullData;
    pullData.cloudId = cloudId;
    pullData.basicSize = fileSize;
    pullData.basicFileName = fileName;
    pullData.basicFileType = fileType;
    pullData.propertiesRotate = 0;
    return pullData;
}

void SetAlbumSourcePath(CloudMediaPullDataDto &pullData, const std::string &lpath)
{
    pullData.propertiesSourcePath = "/storage/emulated/0" + lpath + "/" + pullData.basicFileName;
}

void CloudMediaAssetRetainCompareTest::SetUpTestCase(void)
{
    MediaLibraryUnitTestUtils::Init();
    g_shellToken = IPCSkeleton::GetSelfTokenID();
    MediaLibraryMockTokenUtils::RestoreShellToken(g_shellToken);

    vector<string> perms;
    perms.push_back("ohos.permission.GET_NETWORK_INFO");
    mockToken = new MediaLibraryMockHapToken("com.ohos.medialibrary.medialibrarydata",
        perms);
    for (auto &perm : perms) {
        MediaLibraryMockTokenUtils::GrantPermissionByTest(IPCSkeleton::GetSelfTokenID(), perm, 0);
    }

    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Failed to get rdbstore");
        exit(1);
    }
    SetTables();
}

void CloudMediaAssetRetainCompareTest::TearDownTestCase(void)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MediaLibraryUnitTestUtils::Init();
    }
    ClearAndRestart();
    g_rdbStore = nullptr;
    MediaLibraryDataManager::GetInstance()->ClearMediaLibraryMgr();
    this_thread::sleep_for(chrono::seconds(1));

    if (mockToken != nullptr) {
        delete mockToken;
        mockToken = nullptr;
    }

    MediaLibraryMockTokenUtils::ResetToken();
    SetSelfTokenID(g_shellToken);
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

void CloudMediaAssetRetainCompareTest::SetUp()
{
    ASSERT_NE(g_rdbStore, nullptr);
    ClearAndRestart();
}

void CloudMediaAssetRetainCompareTest::TearDown()
{
}

HWTEST_F(CloudMediaAssetRetainCompareTest, FindDuplicatePhoto_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindDuplicatePhoto_test_001 Start");
    CloudMediaAssetCompareDao dao;
    dao.SetRdbStore(g_rdbStore);

    CloudMediaPullDataDto pullData = BuildPullData("test_cloud_id_001", "test_image.jpg", 1024, 1);

    int32_t maxFileId = 100;
    DuplicatePhotoInfo result = dao.FindDuplicatePhoto(pullData, maxFileId);
    EXPECT_FALSE(result.isValid);
    MEDIA_INFO_LOG("FindDuplicatePhoto_test_001 End");
}

HWTEST_F(CloudMediaAssetRetainCompareTest, FindDuplicatePhoto_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindDuplicatePhoto_test_002 Start");
    CloudMediaAssetCompareDao dao;
    dao.SetRdbStore(g_rdbStore);

    CloudMediaPullDataDto pullData = BuildPullData("", "test_image.jpg", 1024, 1);

    int32_t maxFileId = 100;
    DuplicatePhotoInfo result = dao.FindDuplicatePhoto(pullData, maxFileId);
    EXPECT_FALSE(result.isValid);
    MEDIA_INFO_LOG("FindDuplicatePhoto_test_002 End");
}

HWTEST_F(CloudMediaAssetRetainCompareTest, FindDuplicatePhoto_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindDuplicatePhoto_test_003 Start");
    CloudMediaAssetCompareDao dao;
    dao.SetRdbStore(g_rdbStore);

    CloudMediaPullDataDto pullData = BuildPullData("test_cloud_id_003", "test_image.jpg", 0, 1);

    int32_t maxFileId = 100;
    DuplicatePhotoInfo result = dao.FindDuplicatePhoto(pullData, maxFileId);
    EXPECT_FALSE(result.isValid);
    MEDIA_INFO_LOG("FindDuplicatePhoto_test_003 End");
}

HWTEST_F(CloudMediaAssetRetainCompareTest, FindDuplicatePhoto_test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindDuplicatePhoto_test_004 Start");
    CloudMediaAssetCompareDao dao;
    dao.SetRdbStore(g_rdbStore);

    CloudMediaPullDataDto pullData = BuildPullData("test_cloud_id_004", "", 1024, 1);

    int32_t maxFileId = 100;
    DuplicatePhotoInfo result = dao.FindDuplicatePhoto(pullData, maxFileId);
    EXPECT_FALSE(result.isValid);
    MEDIA_INFO_LOG("FindDuplicatePhoto_test_004 End");
}

HWTEST_F(CloudMediaAssetRetainCompareTest, FindDuplicatePhoto_test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindDuplicatePhoto_test_005 Start");
    CloudMediaAssetCompareDao dao;
    dao.SetRdbStore(g_rdbStore);

    CloudMediaPullDataDto pullData = BuildPullData("test_cloud_id_005", "test_image.jpg", 1024, 1);

    int32_t maxFileId = 0;
    DuplicatePhotoInfo result = dao.FindDuplicatePhoto(pullData, maxFileId);
    EXPECT_FALSE(result.isValid);
    MEDIA_INFO_LOG("FindDuplicatePhoto_test_005 End");
}

HWTEST_F(CloudMediaAssetRetainCompareTest, FindDuplicatePhoto_test_009, TestSize.Level0)
{
    MEDIA_INFO_LOG("FindDuplicatePhoto_test_009 Start");
    CloudMediaAssetCompareDao dao;
    dao.SetRdbStore(g_rdbStore);

    CloudMediaPullDataDto pullData = BuildPullData("test_cloud_id_009", "test_video.mp4", 1024, 2);
    pullData.propertiesRotate = 0;

    int32_t maxFileId = 100;
    DuplicatePhotoInfo result = dao.FindDuplicatePhoto(pullData, maxFileId);
    EXPECT_FALSE(result.isValid);
    MEDIA_INFO_LOG("FindDuplicatePhoto_test_009 End");
}

HWTEST_F(CloudMediaAssetRetainCompareTest, GetMaxFileIdBeforeCompare_test_010, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetMaxFileIdBeforeCompare_test_010 Start");
    CloudMediaAssetCompareDao dao;
    InsertPhotoRow(10, "test.jpg", 1024, 1);
    dao.SetRdbStore(g_rdbStore);

    int32_t maxFileId = dao.GetMaxFileIdBeforeCompare();
    EXPECT_EQ(maxFileId, 10);
    MEDIA_INFO_LOG("GetMaxFileIdBeforeCompare_test_010 End");
}

HWTEST_F(CloudMediaAssetRetainCompareTest, SetRdbStore_test_011, TestSize.Level0)
{
    MEDIA_INFO_LOG("SetRdbStore_test_011 Start");
    CloudMediaAssetCompareDao dao;
    InsertPhotoRow(5, "test.jpg", 1021, 1);
    dao.SetRdbStore(g_rdbStore);
    EXPECT_EQ(dao.GetMaxFileIdBeforeCompare(), 5);

    InsertPhotoRow(6, "test2.jpg", 1022, 1);
    int32_t maxFileId = dao.GetMaxFileIdBeforeCompare();
    EXPECT_EQ(maxFileId, 5);
    MEDIA_INFO_LOG("SetRdbStore_test_011 End");
}

HWTEST_F(CloudMediaAssetRetainCompareTest, FindDuplicatePhoto_test_017, TestSize.Level1)
{
    MEDIA_INFO_LOG("FindDuplicatePhoto_test_017 Start");
    CloudMediaAssetCompareDao dao;
    dao.SetRdbStore(g_rdbStore);

    PhotoRowOptions options;
    options.orientation = 90;
    InsertPhotoRow(12, "test.jpg", 1024, 1, options);

    CloudMediaPullDataDto pullData = BuildPullData("test_cloud_id_017", "test.jpg", 1024, 1);
    pullData.propertiesRotate = -1;

    int32_t maxFileId = 100;
    DuplicatePhotoInfo result = dao.FindDuplicatePhoto(pullData, maxFileId);
    EXPECT_FALSE(result.isValid);
    MEDIA_INFO_LOG("FindDuplicatePhoto_test_017 End");
}

HWTEST_F(CloudMediaAssetRetainCompareTest, GetMaxFileIdBeforeCompare_test_019, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetMaxFileIdBeforeCompare_test_019 Start");
    CloudMediaAssetCompareDao dao;
    dao.SetRdbStore(g_rdbStore);

    int32_t maxFileId = dao.GetMaxFileIdBeforeCompare();
    EXPECT_EQ(maxFileId, 0);
    MEDIA_INFO_LOG("GetMaxFileIdBeforeCompare_test_019 End");
}

HWTEST_F(CloudMediaAssetRetainCompareTest, FindDuplicatePhoto_test_020, TestSize.Level1)
{
    MEDIA_INFO_LOG("FindDuplicatePhoto_test_020 Start");
    CloudMediaAssetCompareDao dao;
    dao.SetRdbStore(g_rdbStore);

    InsertPhotoRow(15, "test.jpg", 1024, 1);

    CloudMediaPullDataDto pullData = BuildPullData("test_cloud_id_020", "test.jpg", 1024, 1);
    pullData.propertiesRotate = 0;

    int32_t maxFileId = 10;
    DuplicatePhotoInfo result = dao.FindDuplicatePhoto(pullData, maxFileId);
    EXPECT_FALSE(result.isValid);
    MEDIA_INFO_LOG("FindDuplicatePhoto_test_020 End");
}

HWTEST_F(CloudMediaAssetRetainCompareTest, FindSamePhotoInAlbum_test_021, TestSize.Level1)
{
    CloudMediaAssetCompareDao dao;
    dao.SetRdbStore(g_rdbStore);
    CloudMediaPullDataDto pullData = BuildPullData("test_cloud_id_021", "album.jpg", 100, 1);
    pullData.propertiesSourcePath = "";
    DuplicatePhotoInfo result = dao.FindSamePhotoInAlbum(pullData, 100);
    EXPECT_FALSE(result.isValid);
}

HWTEST_F(CloudMediaAssetRetainCompareTest, FindSamePhotoWithoutAlbum_test_023, TestSize.Level1)
{
    CloudMediaAssetCompareDao dao;
    dao.SetRdbStore(g_rdbStore);
    PhotoRowOptions options;
    options.orientation = 90;
    InsertPhotoRow(23, "without_album.jpg", 2048, 1, options);

    CloudMediaPullDataDto pullData = BuildPullData("test_cloud_id_023", "without_album.jpg", 2048, 1);
    pullData.propertiesRotate = 0;
    DuplicatePhotoInfo result = dao.FindSamePhotoWithoutAlbum(pullData, 100);
    EXPECT_FALSE(result.isValid);
}

HWTEST_F(CloudMediaAssetRetainCompareTest, FindSamePhotoBySourcePath_test_025, TestSize.Level1)
{
    CloudMediaAssetCompareDao dao;
    dao.SetRdbStore(g_rdbStore);
    CloudMediaPullDataDto pullData = BuildPullData("test_cloud_id_025", "source_empty.jpg", 1024, 1);
    pullData.attributesStoragePath = "";
    DuplicatePhotoInfo result = dao.FindSamePhotoBySourcePath(pullData, 100);
    EXPECT_FALSE(result.isValid);
}

HWTEST_F(CloudMediaAssetRetainCompareTest, FindSamePhotoBySourcePath_test_026, TestSize.Level1)
{
    CloudMediaAssetCompareDao dao;
    dao.SetRdbStore(g_rdbStore);
    PhotoRowOptions options;
    options.hasOwnerAlbumId = true;
    options.ownerAlbumId = 126;
    options.dataPath = "/data/source_filter.jpg";
    options.sourcePath = "/storage/source_filter.jpg";
    InsertPhotoRow(26, "source_filter.jpg", 1024, 1, options);

    CloudMediaPullDataDto pullData = BuildPullData("test_cloud_id_026", "source_filter.jpg", 1024, 1);
    pullData.attributesStoragePath = "/storage/source_filter.jpg";
    pullData.propertiesRotate = 0;
    DuplicatePhotoInfo result = dao.FindSamePhotoBySourcePath(pullData, 100);
    EXPECT_FALSE(result.isValid);
}

HWTEST_F(CloudMediaAssetRetainCompareTest, ExecuteDuplicateQuery_test_028, TestSize.Level1)
{
    CloudMediaAssetCompareDao dao;
    std::vector<NativeRdb::ValueObject> params;
    DuplicatePhotoInfo result = dao.ExecuteDuplicateQuery("SELECT 1;", params);
    EXPECT_FALSE(result.isValid);
}

HWTEST_F(CloudMediaAssetRetainCompareTest, ExecuteDuplicateQuery_test_029, TestSize.Level1)
{
    CloudMediaAssetCompareDao dao;
    dao.SetRdbStore(g_rdbStore);
    std::vector<NativeRdb::ValueObject> params = {9999};
    std::string sql = "SELECT file_id, data, clean_flag, position, real_lcd_visit_time FROM Photos WHERE file_id = ?;";
    DuplicatePhotoInfo result = dao.ExecuteDuplicateQuery(sql, params);
    EXPECT_FALSE(result.isValid);
}

HWTEST_F(CloudMediaAssetRetainCompareTest, GetMediaTypeFromPullData_test_030, TestSize.Level1)
{
    CloudMediaAssetCompareDao dao;
    CloudMediaPullDataDto imageData = BuildPullData("test_cloud_id_030_1", "a.jpg", 100,
        CloudSync::FILE_TYPE_IMAGE);
    CloudMediaPullDataDto videoData = BuildPullData("test_cloud_id_030_2", "a.mp4", 100,
        CloudSync::FILE_TYPE_VIDEO);
    EXPECT_EQ(dao.GetMediaTypeFromPullData(imageData), MEDIA_TYPE_IMAGE);
    EXPECT_EQ(dao.GetMediaTypeFromPullData(videoData), MEDIA_TYPE_VIDEO);
}

HWTEST_F(CloudMediaAssetRetainCompareTest, GetPhotosMaxFileId_test_031, TestSize.Level1)
{
    CloudMediaAssetCompareDao dao;
    InsertPhotoRow(31, "max31.jpg", 100, 1);
    EXPECT_EQ(dao.GetPhotosMaxFileId(), 31);
}
} // namespace Media
} // namespace OHOS

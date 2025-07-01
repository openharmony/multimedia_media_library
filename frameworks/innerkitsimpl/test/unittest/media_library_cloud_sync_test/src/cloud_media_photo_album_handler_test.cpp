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

#define MLOG_TAG "MediaCloudSync"

#include "cloud_media_photo_album_handler_test.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <utime.h>

#include "media_log.h"

#include "album_dao.h"
#include "cloud_check_data.h"
#include "cloud_file_data.h"
#include "cloud_media_data_client.h"
#include "cloud_meta_data.h"
#include "mdk_asset.h"
#include "mdk_database.h"
#include "mdk_error.h"
#include "mdk_record_field.h"
#include "mdk_record.h"
#include "mdk_reference.h"
#include "i_cloud_media_data_handler.h"
#include "cloud_media_data_handler.h"
#include "json/json.h"
#include "json_file_reader.h"
#include "mdk_record_utils.h"
#include "photos_dao.h"

using namespace testing::ext;

namespace OHOS::Media::CloudSync {
DatabaseDataMock CloudMediaPhotoAlbumHandlerTest::dbDataMock_;
void CloudMediaPhotoAlbumHandlerTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
    // Get RdbStore
    int32_t errorCode = 0;
    std::shared_ptr<NativeRdb::RdbStore> rdbStore = MediaLibraryDatabase().GetRdbStore(errorCode);
    int32_t ret = dbDataMock_.SetRdbStore(rdbStore).CheckPoint();
    ret = dbDataMock_.MockData(CloudMediaPhotoAlbumHandlerTest::GetTableMockInfoList());
    MEDIA_INFO_LOG("SetUpTestCase ret: %{public}d", ret);
}

void CloudMediaPhotoAlbumHandlerTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase");
    bool ret = dbDataMock_.Rollback();
    MEDIA_INFO_LOG("TearDownTestCase ret: %{public}d", ret);
}

// SetUp:Execute before each test case
void CloudMediaPhotoAlbumHandlerTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void CloudMediaPhotoAlbumHandlerTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

/**
 * 获取相册创建记录 GetCreatedRecords，结果包含album_plugin记录
 * 期望结果：
 * 输出对应数量的records，records对应字段和album_plugin一致
 */
HWTEST_F(CloudMediaPhotoAlbumHandlerTest, GetCreatedRecords_Known_Album, TestSize.Level1)
{
    std::string tableName = "PhotoAlbum";
    int32_t cloudType = 0;
    int32_t userId = 100;
    std::shared_ptr<CloudMediaDataHandler> dataHandler =
        std::make_shared<CloudMediaDataHandler>(tableName, cloudType, userId);
    std::vector<MDKRecord> records;
    int32_t size = 100;
    int32_t ret = dataHandler->GetCreatedRecords(records, size);
    EXPECT_EQ(ret, 0);
    EXPECT_GT(records.size(), 0);

    // 不包含空相册集合
    std::vector<std::string> lpaths = {
        "/tencent/QQ_Images",
        "/Pictures/Screenshots",
    };
    std::map<std::string, std::vector<std::string>> knownAlbumInfo = {
        {"/tencent/QQ_Images", {"QQ", "default-album-101", "com.tencent.mqq", "0"}},
        {"/Tencent/MicroMsg/WeiXin", {"微信", "default-album-102", "com.tencent.wechat", "0"}},
    };

    int32_t num = 0;
    for (auto &record : records) {
        MDKRecordAlbumData data(record);
        auto it = knownAlbumInfo.find(data.GetCloudId().value_or(""));
        if (it != knownAlbumInfo.end()) {
            EXPECT_EQ(data.GetAlbumName().value_or("albumName"), it->second[0]);
            EXPECT_EQ(data.GetCloudId().value_or("cloudId"), it->second[1]);
            EXPECT_EQ(data.GetBundleName().value_or("bundleName"), it->second[2]);
            EXPECT_EQ(std::to_string(data.GetPriority().value_or(-1)), it->second[3]);
            EXPECT_EQ(data.GetlPath().value_or("lpath"), it->first);
        }
    }
    EXPECT_EQ(num, 0);
}

/**
 * 获取相册创建记录 GetCreatedRecords，不包含空相册的记录
 * 期望结果：
 * 输出对应数量的records，records对应字段和实际修改一致
 */
HWTEST_F(CloudMediaPhotoAlbumHandlerTest, GetCreatedRecords_Empty_Album, TestSize.Level1)
{
    std::string tableName = "PhotoAlbum";
    int32_t cloudType = 0;
    int32_t userId = 100;
    std::shared_ptr<CloudMediaDataHandler> dataHandler =
        std::make_shared<CloudMediaDataHandler>(tableName, cloudType, userId);
    std::vector<MDKRecord> records;
    int32_t size = 100;
    int32_t ret = dataHandler->GetCreatedRecords(records, size);
    EXPECT_EQ(ret, 0);
    EXPECT_GT(records.size(), 0);

    // 不包含空相册集合
    std::vector<std::string> cloudIds = {"373b364a41e54ebf912b3414aeabe963507a901b2b1a4332939d51ed54ff97c5",
                                         "373b364a41e54ebf912b3424aeabe963507a901b2b1a4332939d51ed54ff97c6",
                                         "373b364a41e54ebf912b3424aeabe963507a901b2b1a4332939d51ed54ff97c7",
                                         "373b364a41e54ebf912b3464aeabe963507a901b2b1a4332939d58ed54ff97c8",
                                         "373b364a41e54ebf912b3464aeabe963507a901b2b1a4332939d58ed54ff97c9"};

    int32_t num = 0;
    for (auto &record : records) {
        for (auto &cloudId : cloudIds) {
            if (record.GetRecordId() == cloudId) {
                num++;
            }
        }
    }
    EXPECT_EQ(num, 0);
}

/**
 * 获取相册创建记录 GetCreatedRecords，获取到不为空相册记录
 * 期望结果：
 * 输出对应数量的records，records对应字段和实际修改一致
 */
HWTEST_F(CloudMediaPhotoAlbumHandlerTest, GetCreatedRecords_Not_Empty_Album, TestSize.Level1)
{
    std::string tableName = "PhotoAlbum";
    int32_t cloudType = 0;
    int32_t userId = 100;
    std::shared_ptr<CloudMediaDataHandler> dataHandler =
        std::make_shared<CloudMediaDataHandler>(tableName, cloudType, userId);
    std::vector<MDKRecord> records;
    int32_t size = 100;
    int32_t ret = dataHandler->GetCreatedRecords(records, size);
    EXPECT_EQ(ret, 0);
    EXPECT_GT(records.size(), 0);  //默认数据

    int32_t num = 0;
    for (auto &record : records) {
        MDKRecordAlbumData data = MDKRecordAlbumData(record);
        if (data.GetAlbumName().value_or("") != ".hiddenAlbum") {
            num++;
        }
    }
    EXPECT_GT(num, 0);
}

/**
 * 获取相册创建记录 GetCreatedRecords，修改相册名字
 * 期望结果：
 * 输出对应数量的records，records对应字段和实际修改一致
 */
HWTEST_F(CloudMediaPhotoAlbumHandlerTest, GetCreatedRecords_Update_AlbumName, TestSize.Level1)
{
    // 先获取记录
    TestUtils::AlbumDao dao = TestUtils::AlbumDao();
    std::vector<std::string> cloudIds = {"default-album-200-/Pictures/Users/S-202504021638"};
    std::vector<CloudSync::PhotoAlbumPo> albums = dao.QueryByCloudIds(cloudIds);
    EXPECT_EQ(albums.size(), 1);

    int32_t albumId = -1;
    for (auto &album : albums) {
        albumId = album.albumId.value_or(-1);
    }
    EXPECT_NE(albumId, -1);

    // 更新相册名称
    int32_t changeRows = dao.UpdatePhotoAlbumName(albumId, "SS");
    EXPECT_EQ(changeRows, 1);

    std::string tableName = "PhotoAlbum";
    int32_t cloudType = 0;
    int32_t userId = 100;
    std::shared_ptr<CloudMediaDataHandler> dataHandler =
        std::make_shared<CloudMediaDataHandler>(tableName, cloudType, userId);
    std::vector<MDKRecord> records;
    int32_t size = 100;
    int32_t ret = dataHandler->GetCreatedRecords(records, size);
    EXPECT_EQ(ret, 0);
    EXPECT_GT(records.size(), 0);
    std::string albumName = "";
    for (auto &record : records) {
        if (record.GetRecordId() == "default-album-200-/Pictures/Users/S-202504021638") {
            MDKRecordAlbumData data = MDKRecordAlbumData(record);
            albumName = data.GetAlbumName().value_or("");
        }
    }
    EXPECT_EQ(albumName, "SS");
}

/**
 * 获取相册创建记录 GetMetaModifiedRecords
 * 期望结果：
 * 输出对应数量的records，records对应字段和实际修改一致
 */
HWTEST_F(CloudMediaPhotoAlbumHandlerTest, GetMetaModifiedRecords, TestSize.Level1)
{
    std::string tableName = "PhotoAlbum";
    int32_t cloudType = 0;
    int32_t userId = 100;
    std::shared_ptr<CloudMediaDataHandler> dataHandler =
        std::make_shared<CloudMediaDataHandler>(tableName, cloudType, userId);
    std::vector<MDKRecord> records;
    int32_t size = 100;
    int32_t ret = dataHandler->GetMetaModifiedRecords(records, size);
    EXPECT_EQ(ret, 0);
    EXPECT_GT(records.size(), 0);

    std::string cloudId = "default-album-200-/Pictures/Users/T-202504021638";
    int32_t num = 0;
    for (auto &record : records) {
        if (record.GetRecordId() == cloudId) {
            num++;
        }
    }
    EXPECT_EQ(num, 1);
}

// album does not handle this operation <GetFileModifiedRecords>.
HWTEST_F(CloudMediaPhotoAlbumHandlerTest, GetFileModifiedRecords, TestSize.Level1)
{
    EXPECT_TRUE(true);
}

HWTEST_F(CloudMediaPhotoAlbumHandlerTest, GetDeletedRecords, TestSize.Level1)
{
    std::string tableName = "PhotoAlbum";
    int32_t cloudType = 0;
    int32_t userId = 100;
    std::shared_ptr<CloudMediaDataHandler> dataHandler =
        std::make_shared<CloudMediaDataHandler>(tableName, cloudType, userId);
    std::vector<MDKRecord> records;
    int32_t size = 100;
    int32_t ret = dataHandler->GetDeletedRecords(records, size);
    EXPECT_EQ(ret, 0);
    EXPECT_GT(records.size(), 0);
    std::vector<MDKRecord> targetRecords;
    JsonFileReader reader("/data/test/cloudsync/album_handler_get_delete_record_result.json");
    reader.ConvertToMDKRecordVector(targetRecords);
    EXPECT_GT(targetRecords.size(), 0);
    MDKRecordUtils utils;
    std::vector<std::string> checkFields = {"album_type",    "album_subtype", "logicType",      "date_added",
                                            "date_modified", "bundle_name",   "albumName",      "localPath",
                                            "albumId",       "type",          "local_language", "emptyShow"};
    int32_t checkCount = 0;
    for (auto &record : records) {
        for (auto &target : targetRecords) {
            if (record.GetRecordId() == target.GetRecordId()) {
                EXPECT_TRUE(utils.Equals(record, target, checkFields, MDKRecordUtils::RecordType::ALBUM));
                checkCount++;
            }
        }
    }
    EXPECT_EQ(checkCount, targetRecords.size());
}

/**
 * 获取相册删除记录 GetDeletedRecords
 * 期望结果：
 * 输出对应数量的records，records对应字段和实际修改一致
 */
HWTEST_F(CloudMediaPhotoAlbumHandlerTest, GetDeletedRecords_Delete, TestSize.Level1)
{
    TestUtils::AlbumDao dao = TestUtils::AlbumDao();
    std::string cloudId = "default-album-200-/Pictures/Users/U-202504021520";
    int32_t deleteRows = dao.DeleteAlbumByCloudId(cloudId, 4);
    EXPECT_EQ(deleteRows, 1);

    std::string tableName = "PhotoAlbum";
    int32_t cloudType = 0;
    int32_t userId = 100;
    std::shared_ptr<CloudMediaDataHandler> dataHandler =
        std::make_shared<CloudMediaDataHandler>(tableName, cloudType, userId);
    std::vector<MDKRecord> records;
    int32_t size = 100;
    int32_t ret = dataHandler->GetDeletedRecords(records, size);
    EXPECT_EQ(ret, 0);
    EXPECT_GT(records.size(), 0);

    int32_t num = 0;
    for (auto &record : records) {
        if (record.GetRecordId() == cloudId) {
            num++;
        }
    }
    EXPECT_EQ(num, 1);
}

/**
 * 获取相册删除记录 GetDeletedRecords 但是相册非空，需要修改dirty为new
 * 期望结果：
 * 非空相册dirty修改为new
 */
HWTEST_F(CloudMediaPhotoAlbumHandlerTest, GetDeletedRecords_notEmptyAlbumSetNew, TestSize.Level1)
{
    std::vector<std::string> cloudIds = {"default-album-200-/Pictures/Users/U-202504113456"};
    std::string tableName = "PhotoAlbum";
    int32_t cloudType = 0;
    int32_t userId = 100;
    std::shared_ptr<CloudMediaDataHandler> dataHandler =
        std::make_shared<CloudMediaDataHandler>(tableName, cloudType, userId);
    std::vector<MDKRecord> records;
    int32_t size = 100;
    int32_t ret = dataHandler->GetDeletedRecords(records, size);
    EXPECT_EQ(ret, 0);
    //预期没有获取到record或者获取到的record中不包含目标record
    for (auto &record : records) {
        for (auto cloudId : cloudIds) {
            EXPECT_TRUE(record.GetRecordId() != cloudId) << "find album_id:" << cloudId;
        }
    }
    //预期目标record的dirty已修改为new
    TestUtils::AlbumDao dao = TestUtils::AlbumDao();
    std::vector<PhotoAlbumPo> albumList = dao.QueryByCloudIds(cloudIds);
    EXPECT_EQ(albumList.size(), cloudIds.size());
    for (auto cloudId : cloudIds) {
        PhotoAlbumPo album = PhotoAlbumPo();
        EXPECT_EQ(dao.GetAlbumByCloudId(albumList, cloudId, album), 0);
        EXPECT_EQ(album.dirty.value_or(-1), static_cast<int32_t>(DirtyType::TYPE_NEW));
    }
}

HWTEST_F(CloudMediaPhotoAlbumHandlerTest, GetCopyRecords, TestSize.Level1)
{
    EXPECT_TRUE(true);
}

/**
 * 上行相册记录 OnCreateRecords 一个正常，一个异常
 * 期望结果：
 * 输出对应数量的records，异常未上行，正常上行
 */
HWTEST_F(CloudMediaPhotoAlbumHandlerTest, OnCreateRecords_Has_Error, TestSize.Level1)
{
    std::string tableName = "PhotoAlbum";
    int32_t cloudType = 0;
    int32_t userId = 100;
    std::shared_ptr<CloudMediaDataHandler> dataHandler =
        std::make_shared<CloudMediaDataHandler>(tableName, cloudType, userId);
    std::map<std::string, MDKRecordOperResult> map;
    JsonFileReader reader("/data/test/cloudsync/albumhandler/oncreatedrecords_has_error.json");
    reader.ConvertToMDKRecordOperResultMap(map);
    int32_t failSize = 0;
    int32_t ret = dataHandler->OnCreateRecords(map, failSize);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(failSize, 1);

    // 校验数据库结果
    TestUtils::AlbumDao dao = TestUtils::AlbumDao();
    std::vector<std::string> cloudIds = {"default-album-200-/Pictures/Users/Ab-202504021601"};
    std::vector<CloudSync::PhotoAlbumPo> albums = dao.QueryByCloudIds(cloudIds);
    EXPECT_EQ(cloudIds.size(), albums.size());
    for (auto cloudId : cloudIds) {
        PhotoAlbumPo album = PhotoAlbumPo();
        EXPECT_EQ(dao.GetAlbumByCloudId(albums, cloudId, album), 0);
        auto it = map.find(cloudId);
        if (it != map.end()) {
            EXPECT_NE(album.dirty.value_or(-1), static_cast<int32_t>(DirtyTypes::TYPE_SYNCED)) << it->first;
        }
    }
}

/**
 * 上行相册记录 OnCreateRecords 没有异常
 * 期望结果：
 * 输出对应数量的records，异常未上行，正常上行
 */
HWTEST_F(CloudMediaPhotoAlbumHandlerTest, OnCreateRecords_No_Error, TestSize.Level1)
{
    std::string tableName = "PhotoAlbum";
    int32_t cloudType = 0;
    int32_t userId = 100;
    std::shared_ptr<CloudMediaDataHandler> dataHandler =
        std::make_shared<CloudMediaDataHandler>(tableName, cloudType, userId);
    std::map<std::string, MDKRecordOperResult> map;
    JsonFileReader reader("/data/test/cloudsync/albumhandler/oncreatedrecords_no_error.json");
    reader.ConvertToMDKRecordOperResultMap(map);
    int32_t failSize = 0;
    int32_t ret = dataHandler->OnCreateRecords(map, failSize);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(failSize, 0);

    // 校验数据库结果
    TestUtils::AlbumDao dao = TestUtils::AlbumDao();
    std::vector<std::string> cloudIds = {"default-album-200-/Pictures/Users/Aa-202504021601"};
    std::vector<CloudSync::PhotoAlbumPo> albums = dao.QueryByCloudIds(cloudIds);
    EXPECT_EQ(albums.size(), cloudIds.size());
    for (auto cloudId : cloudIds) {
        PhotoAlbumPo album = PhotoAlbumPo();
        EXPECT_EQ(dao.GetAlbumByCloudId(albums, cloudId, album), 0);
        EXPECT_EQ(album.dirty.value_or(0), 0);
    }
}

/**
 * 上行Mdirty记录 OnMdirtyRecords 一个异常，一个正常
 * 期望结果：
 * 输出对应数量的records，异常未上行，正常上行
 */
HWTEST_F(CloudMediaPhotoAlbumHandlerTest, OnMdirtyRecords_Has_Error, TestSize.Level1)
{
    std::string tableName = "PhotoAlbum";
    int32_t cloudType = 0;
    int32_t userId = 100;
    std::shared_ptr<CloudMediaDataHandler> dataHandler =
        std::make_shared<CloudMediaDataHandler>(tableName, cloudType, userId);
    std::map<std::string, MDKRecordOperResult> map{
        {"default-album-200-/Pictures/Users/W-202504021520", MDKLocalErrorCode::NO_ERROR},
        {"default-album-200-/Pictures/Users/X-202504021520", MDKLocalErrorCode::IPC_SEND_FAILED},
    };
    int32_t failSize = 0;
    int32_t ret = dataHandler->OnMdirtyRecords(map, failSize);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(failSize, 1);

    // 校验数据库结果
    TestUtils::AlbumDao dao = TestUtils::AlbumDao();
    std::vector<std::string> cloudIds = {"default-album-200-/Pictures/Users/W-202504021520",
                                         "default-album-200-/Pictures/Users/X-202504021520"};
    std::vector<CloudSync::PhotoAlbumPo> albums = dao.QueryByCloudIds(cloudIds);
    for (auto cloudId : cloudIds) {
        PhotoAlbumPo album = PhotoAlbumPo();
        EXPECT_EQ(dao.GetAlbumByCloudId(albums, cloudId, album), 0);
        if (cloudId == "default-album-200-/Pictures/Users/W-202504021520") {
            EXPECT_EQ(album.dirty.value_or(0), 0);
        }
        if (cloudId == "default-album-200-/Pictures/Users/X-202504021520") {
            EXPECT_GT(album.dirty.value_or(0), 0);
        }
    }
}

/**
 * 上行Mdirty记录 OnMdirtyRecords 没有异常
 * 期望结果：
 * 输出对应数量的records，异常未上行，正常上行
 */
HWTEST_F(CloudMediaPhotoAlbumHandlerTest, OnMdirtyRecords_No_Error, TestSize.Level1)
{
    std::string tableName = "PhotoAlbum";
    int32_t cloudType = 0;
    int32_t userId = 100;
    std::shared_ptr<CloudMediaDataHandler> dataHandler =
        std::make_shared<CloudMediaDataHandler>(tableName, cloudType, userId);
    std::map<std::string, MDKRecordOperResult> map{
        {"default-album-200-/Pictures/Users/W-202504021520", MDKLocalErrorCode::NO_ERROR},
        {"default-album-200-/Pictures/Users/X-202504021520", MDKLocalErrorCode::NO_ERROR},
    };
    int32_t failSize = 0;
    int32_t ret = dataHandler->OnMdirtyRecords(map, failSize);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(failSize, 0);

    // 校验数据库结果
    TestUtils::AlbumDao dao = TestUtils::AlbumDao();
    std::vector<std::string> cloudIds = {"default-album-200-/Pictures/Users/W-202504021520",
                                         "default-album-200-/Pictures/Users/X-202504021520"};
    std::vector<CloudSync::PhotoAlbumPo> albums = dao.QueryByCloudIds(cloudIds);
    for (auto cloudId : cloudIds) {
        PhotoAlbumPo album = PhotoAlbumPo();
        EXPECT_EQ(dao.GetAlbumByCloudId(albums, cloudId, album), 0);
        EXPECT_EQ(album.dirty.value_or(0), 0);
    }
}

HWTEST_F(CloudMediaPhotoAlbumHandlerTest, OnFdirtyRecords, TestSize.Level1)
{
    std::string tableName = "PhotoAlbum";
    int32_t cloudType = 0;
    int32_t userId = 100;
    std::shared_ptr<CloudMediaDataHandler> dataHandler =
        std::make_shared<CloudMediaDataHandler>(tableName, cloudType, userId);
    std::map<std::string, MDKRecordOperResult> map{
        {"373b364a41e54ebf912b3424aeabe963507a901b2b1a4332939d51ed54ff97c7", MDKLocalErrorCode::NO_ERROR},
        {"373b364a41e54ebf912b3424aeabe963507a901b2b1a4332939d51ed54ff97c6", MDKLocalErrorCode::NO_ERROR},
    };
    int32_t failSize = 0;
    int32_t ret = dataHandler->OnFdirtyRecords(map, failSize);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(failSize, 0);
}

/**
 * 上传数据结果中存在上传失败
 * 期望结果：
 * 删除成功的记录在数据库中查询不到，删除失败的记录可以查询到
 */
HWTEST_F(CloudMediaPhotoAlbumHandlerTest, OnDeleteRecords_Has_Error, TestSize.Level1)
{
    std::string tableName = "PhotoAlbum";
    int32_t cloudType = 0;
    int32_t userId = 100;
    std::shared_ptr<CloudMediaDataHandler> dataHandler =
        std::make_shared<CloudMediaDataHandler>(tableName, cloudType, userId);
    std::map<std::string, MDKRecordOperResult> map{
        {"default-album-200-/Pictures/Users/Y-202504021601", MDKLocalErrorCode::NO_ERROR},
        {"default-album-200-/Pictures/Users/Z-202504021601", MDKLocalErrorCode::IPC_SEND_FAILED},
    };
    int32_t failSize = 0;
    int32_t ret = dataHandler->OnDeleteRecords(map, failSize);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(failSize, 1);

    TestUtils::AlbumDao dao = TestUtils::AlbumDao();
    std::vector<std::string> cloudIds = {"default-album-200-/Pictures/Users/Y-202504021601",
                                         "default-album-200-/Pictures/Users/Z-202504021601"};
    std::vector<CloudSync::PhotoAlbumPo> albums = dao.QueryByCloudIds(cloudIds);
    EXPECT_GT(albums.size(), 0);

    for (auto cloudId : cloudIds) {
        if (cloudId == "default-album-200-/Pictures/Users/Z-202504021601") {
            PhotoAlbumPo album = PhotoAlbumPo();
            EXPECT_EQ(dao.GetAlbumByCloudId(albums, cloudId, album), 0);
            EXPECT_EQ(album.dirty.value_or(0), 4);
        }
    }
}

/**
 * 上传数据结果中全部成功
 * 期望结果：
 * 删除成功的记录在数据库中查询不到
 */
HWTEST_F(CloudMediaPhotoAlbumHandlerTest, OnDeleteRecords_No_Error, TestSize.Level1)
{
    std::string tableName = "PhotoAlbum";
    int32_t cloudType = 0;
    int32_t userId = 100;
    std::shared_ptr<CloudMediaDataHandler> dataHandler =
        std::make_shared<CloudMediaDataHandler>(tableName, cloudType, userId);
    std::map<std::string, MDKRecordOperResult> map{
        {"default-album-200-/Pictures/Users/Y-202504021601", MDKLocalErrorCode::NO_ERROR},
        {"default-album-200-/Pictures/Users/Z-202504021601", MDKLocalErrorCode::NO_ERROR},
    };
    int32_t failSize = 0;
    int32_t ret = dataHandler->OnDeleteRecords(map, failSize);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(failSize, 0);

    TestUtils::AlbumDao dao = TestUtils::AlbumDao();
    std::vector<std::string> cloudIds = {"default-album-200-/Pictures/Users/Y-202504021601",
                                         "default-album-200-/Pictures/Users/Z-202504021601"};
    std::vector<CloudSync::PhotoAlbumPo> albums = dao.QueryByCloudIds(cloudIds);
    EXPECT_EQ(albums.size(), 0);
}

// Album does not implement the following methods [OnCopyRecords]
HWTEST_F(CloudMediaPhotoAlbumHandlerTest, OnCopyRecords, TestSize.Level1)
{
    EXPECT_TRUE(true);
}

HWTEST_F(CloudMediaPhotoAlbumHandlerTest, OnCompletePush, TestSize.Level1)
{
    EXPECT_TRUE(true);
}

HWTEST_F(CloudMediaPhotoAlbumHandlerTest, OnStartSync, TestSize.Level1)
{
    EXPECT_TRUE(true);
}

HWTEST_F(CloudMediaPhotoAlbumHandlerTest, OnCompleteSync, TestSize.Level1)
{
    EXPECT_TRUE(true);
}

HWTEST_F(CloudMediaPhotoAlbumHandlerTest, OnDentryFileInsert, TestSize.Level1)
{
    EXPECT_TRUE(true);
}

// Album does not implement the following methods [GetRetryRecords]
HWTEST_F(CloudMediaPhotoAlbumHandlerTest, GetRetryRecords, TestSize.Level1)
{
    EXPECT_TRUE(true);
}

/**
 * OnCompletePull
 * 期望结果：
 * dirty = 6 ，count != 0 修改dirty，否则删除
 */
HWTEST_F(CloudMediaPhotoAlbumHandlerTest, OnCompletePull, TestSize.Level1)
{
    TestUtils::AlbumDao dao = TestUtils::AlbumDao();
    std::vector<CloudSync::PhotoAlbumPo> albums = dao.QueryAllAlbums();
    EXPECT_GT(albums.size(), 0);

    std::vector<CloudSync::PhotoAlbumPo> albums2;
    for (auto album : albums) {
        if (album.dirty.value_or(-1) == 6) {
            albums2.emplace_back(album);
        }
    }

    std::string tableName = "PhotoAlbum";
    int32_t cloudType = 0;
    int32_t userId = 100;
    std::shared_ptr<CloudMediaDataHandler> dataHandler =
        std::make_shared<CloudMediaDataHandler>(tableName, cloudType, userId);
    int32_t ret = dataHandler->OnCompletePull();
    EXPECT_EQ(ret, 0);
    /* 变更：取消预期 - dirty = 6 ，count != 0 修改dirty，否则删除；
    下一步：使用监听器处理消息
    std::vector<CloudSync::PhotoAlbumPo> albums3 = dao.QueryAllAlbums();
    EXPECT_GT(albums3.size(), 0);

    int32_t num = 0;
    for (auto album_1 : albums2) {
        for (auto album_2 : albums3) {
            if (album_1.albumId.value_or(-1) == album_2.albumId.value_or(-1)) {
                EXPECT_EQ(album_2.dirty.value_or(-1), 1) << "album_2 id:" << album_2.cloudId.value_or("");
                num--;
            }
        }
        num++;
    }
    if (num >= 0) {
        EXPECT_TRUE(true);
    }
    */
}
}  // namespace OHOS::Media::CloudSync
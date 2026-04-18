/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "media_lcd_size_task_test.h"

#include "media_lcd_size_task.h"

#include "media_column.h"
#include "media_log.h"
#include "media_upgrade.h"
#include "medialibrary_errno.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"

using namespace testing::ext;
using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS::Media::Background {
constexpr int32_t TEST_WIDTH_1000 = 1000;
constexpr int32_t TEST_HEIGHT_2000 = 2000;
constexpr int32_t TEST_WIDTH_2000 = 2000;
constexpr int32_t TEST_HEIGHT_1000 = 1000;
constexpr int32_t PHOTO_CLOUD = 2;
constexpr int32_t PHOTO_BOTH = 3;

static shared_ptr<MediaLibraryRdbStore> g_rdbStoreLcdSize = nullptr;
static int64_t g_testFileId1 = 0;
static int64_t g_testFileId2 = 0;
static int64_t g_testFileId3 = 0;

static void CleanTestTables()
{
    std::vector<std::string> dropTableList = {
        PhotoColumn::PHOTOS_TABLE,
    };
    for (auto &dropTable : dropTableList) {
        std::string dropSql = "DROP TABLE IF EXISTS " + dropTable + ";";
        int32_t ret = g_rdbStoreLcdSize->ExecuteSql(dropSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Drop %{public}s table failed", dropTable.c_str());
            return;
        }
        MEDIA_DEBUG_LOG("Drop %{public}s table success", dropTable.c_str());
    }
}

static void SetTables()
{
    std::vector<std::string> createTableSqlList = {
        PhotoUpgrade::CREATE_PHOTO_TABLE,
    };
    for (auto &createTableSql : createTableSqlList) {
        int32_t ret = g_rdbStoreLcdSize->ExecuteSql(createTableSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Execute sql %{private}s failed", createTableSql.c_str());
            return;
        }
        MEDIA_DEBUG_LOG("Execute sql %{private}s success", createTableSql.c_str());
    }
}

static void InsertTestDatas()
{
    NativeRdb::ValuesBucket values1;
    values1.PutInt(MediaColumn::MEDIA_TYPE, MEDIA_TYPE_IMAGE);
    values1.PutInt(PhotoColumn::PHOTO_HEIGHT, TEST_HEIGHT_2000);
    values1.PutInt(PhotoColumn::PHOTO_WIDTH, TEST_WIDTH_1000);
    values1.PutString(PhotoColumn::PHOTO_LCD_SIZE, "1000:2000");
    values1.PutInt(PhotoColumn::PHOTO_POSITION, PHOTO_CLOUD);
    values1.PutInt(PhotoColumn::PHOTO_CLEAN_FLAG, 0);
    int32_t ret = g_rdbStoreLcdSize->Insert(g_testFileId1, PhotoColumn::PHOTOS_TABLE, values1);
    CHECK_AND_PRINT_LOG(ret == NativeRdb::E_OK, "Insert test data1 failed, ret=%{public}d", ret);

    NativeRdb::ValuesBucket values2;
    values2.PutInt(MediaColumn::MEDIA_TYPE, MEDIA_TYPE_IMAGE);
    values2.PutInt(PhotoColumn::PHOTO_HEIGHT, TEST_HEIGHT_1000);
    values2.PutInt(PhotoColumn::PHOTO_WIDTH, TEST_WIDTH_2000);
    values2.PutString(PhotoColumn::PHOTO_LCD_SIZE, "1000:2000");
    values2.PutInt(PhotoColumn::PHOTO_POSITION, PHOTO_CLOUD);
    values2.PutInt(PhotoColumn::PHOTO_CLEAN_FLAG, 0);
    ret = g_rdbStoreLcdSize->Insert(g_testFileId2, PhotoColumn::PHOTOS_TABLE, values2);
    CHECK_AND_PRINT_LOG(ret == NativeRdb::E_OK, "Insert test data2 failed, ret=%{public}d", ret);

    NativeRdb::ValuesBucket values3;
    values3.PutInt(MediaColumn::MEDIA_TYPE, MEDIA_TYPE_IMAGE);
    values3.PutInt(PhotoColumn::PHOTO_HEIGHT, TEST_HEIGHT_1000);
    values3.PutInt(PhotoColumn::PHOTO_WIDTH, TEST_WIDTH_1000);
    values3.PutString(PhotoColumn::PHOTO_LCD_SIZE, "");
    values3.PutInt(PhotoColumn::PHOTO_POSITION, PHOTO_BOTH);
    values3.PutInt(PhotoColumn::PHOTO_CLEAN_FLAG, 0);
    ret = g_rdbStoreLcdSize->Insert(g_testFileId3, PhotoColumn::PHOTOS_TABLE, values3);
    CHECK_AND_PRINT_LOG(ret == NativeRdb::E_OK, "Insert test data3 failed, ret=%{public}d", ret);
}

void MediaLibraryLcdSizeTaskTest::SetUpTestCase(void)
{
    MediaLibraryUnitTestUtils::Init();
    g_rdbStoreLcdSize = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (g_rdbStoreLcdSize == nullptr) {
        MEDIA_ERR_LOG("Start MediaLibraryLcdSizeTaskTest failed, can not get g_rdbStore");
        exit(1);
    }
    CleanTestTables();
    SetTables();
    InsertTestDatas();
    MEDIA_INFO_LOG("MediaLibraryLcdSizeTaskTest SetUpTestCase");
}

void MediaLibraryLcdSizeTaskTest::TearDownTestCase(void)
{
    CleanTestTables();
    MEDIA_INFO_LOG("MediaLibraryLcdSizeTaskTest TearDownTestCase");
}

void MediaLibraryLcdSizeTaskTest::SetUp() {}

void MediaLibraryLcdSizeTaskTest::TearDown(void) {}

/**
 * 测试目的：验证ParseLcdSize方法能够正确解析有效的LCD尺寸字符串
 * 测试场景：输入格式为"width:height"的有效字符串
 * 预期结果：解析成功，返回true，宽高值正确
 */
HWTEST_F(MediaLibraryLcdSizeTaskTest, ParseLcdSize_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("Begin ParseLcdSize_test_001");
    auto task = std::make_shared<MediaLcdSizeTask>();
    ASSERT_NE(task, nullptr);
    int32_t lcdWidth = 0;
    int32_t lcdHeight = 0;
    string lcdSize = "1920:1080";
    bool result = task->ParseLcdSize(lcdSize, lcdWidth, lcdHeight);
    EXPECT_EQ(result, true);
    EXPECT_EQ(lcdWidth, 1920);
    EXPECT_EQ(lcdHeight, 1080);
    MEDIA_INFO_LOG("End ParseLcdSize_test_001");
}

/**
 * 测试目的：验证ParseLcdSize方法处理空字符串时返回false
 * 测试场景：输入空字符串
 * 预期结果：返回false
 */
HWTEST_F(MediaLibraryLcdSizeTaskTest, ParseLcdSize_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("Begin ParseLcdSize_test_002");
    auto task = std::make_shared<MediaLcdSizeTask>();
    ASSERT_NE(task, nullptr);
    int32_t lcdWidth = 0;
    int32_t lcdHeight = 0;
    string lcdSize = "";
    bool result = task->ParseLcdSize(lcdSize, lcdWidth, lcdHeight);
    EXPECT_EQ(result, false);
    MEDIA_INFO_LOG("End ParseLcdSize_test_002");
}

/**
 * 测试目的：验证ParseLcdSize方法处理缺少分隔符的字符串时返回false
 * 测试场景：输入没有冒号分隔符的字符串
 * 预期结果：返回false
 */
HWTEST_F(MediaLibraryLcdSizeTaskTest, ParseLcdSize_test_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("Begin ParseLcdSize_test_003");
    auto task = std::make_shared<MediaLcdSizeTask>();
    ASSERT_NE(task, nullptr);
    int32_t lcdWidth = 0;
    int32_t lcdHeight = 0;
    string lcdSize = "19201080";
    bool result = task->ParseLcdSize(lcdSize, lcdWidth, lcdHeight);
    EXPECT_EQ(result, false);
    MEDIA_INFO_LOG("End ParseLcdSize_test_003");
}

/**
 * 测试目的：验证ParseLcdSize方法处理无效数字字符串时返回false
 * 测试场景：宽度部分为非数字字符串
 * 预期结果：返回false
 */
HWTEST_F(MediaLibraryLcdSizeTaskTest, ParseLcdSize_test_004, TestSize.Level1)
{
    MEDIA_INFO_LOG("Begin ParseLcdSize_test_004");
    auto task = std::make_shared<MediaLcdSizeTask>();
    ASSERT_NE(task, nullptr);
    int32_t lcdWidth = 0;
    int32_t lcdHeight = 0;
    string lcdSize = "abc:1080";
    bool result = task->ParseLcdSize(lcdSize, lcdWidth, lcdHeight);
    EXPECT_EQ(result, false);
    MEDIA_INFO_LOG("End ParseLcdSize_test_004");
}

/**
 * 测试目的：验证ParseLcdSize方法处理高度为非数字时返回false
 * 测试场景：高度部分为非数字字符串
 * 预期结果：返回false
 */
HWTEST_F(MediaLibraryLcdSizeTaskTest, ParseLcdSize_test_005, TestSize.Level1)
{
    MEDIA_INFO_LOG("Begin ParseLcdSize_test_005");
    auto task = std::make_shared<MediaLcdSizeTask>();
    ASSERT_NE(task, nullptr);
    int32_t lcdWidth = 0;
    int32_t lcdHeight = 0;
    string lcdSize = "1920:abc";
    bool result = task->ParseLcdSize(lcdSize, lcdWidth, lcdHeight);
    EXPECT_EQ(result, false);
    MEDIA_INFO_LOG("End ParseLcdSize_test_005");
}

/**
 * 测试目的：验证ParseLcdSize方法处理特殊格式字符串
 * 测试场景：宽高相等的情况
 * 预期结果：正确解析
 */
HWTEST_F(MediaLibraryLcdSizeTaskTest, ParseLcdSize_test_006, TestSize.Level1)
{
    MEDIA_INFO_LOG("Begin ParseLcdSize_test_006");
    auto task = std::make_shared<MediaLcdSizeTask>();
    ASSERT_NE(task, nullptr);
    int32_t lcdWidth = 0;
    int32_t lcdHeight = 0;
    string lcdSize = "1000:1000";
    bool result = task->ParseLcdSize(lcdSize, lcdWidth, lcdHeight);
    EXPECT_EQ(result, true);
    EXPECT_EQ(lcdWidth, TEST_WIDTH_1000);
    EXPECT_EQ(lcdHeight, TEST_HEIGHT_1000);
    MEDIA_INFO_LOG("End ParseLcdSize_test_006");
}

/**
 * 测试目的：验证IsSpecialAsset方法识别特殊资产
 * 测试场景：照片宽>高，LCD高>宽，方向不一致
 * 预期结果：返回true，识别为特殊资产
 */
HWTEST_F(MediaLibraryLcdSizeTaskTest, IsSpecialAsset_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("Begin IsSpecialAsset_test_001");
    auto task = std::make_shared<MediaLcdSizeTask>();
    ASSERT_NE(task, nullptr);
    LcdAssetInfo assetInfo;
    assetInfo.photoWidth = TEST_WIDTH_2000;
    assetInfo.photoHeight = TEST_HEIGHT_1000;
    assetInfo.lcdSize = "1000:2000";
    bool result = task->IsSpecialAsset(assetInfo);
    EXPECT_EQ(result, true);
    EXPECT_EQ(assetInfo.lcdWidth, TEST_WIDTH_1000);
    EXPECT_EQ(assetInfo.lcdHeight, TEST_HEIGHT_2000);
    MEDIA_INFO_LOG("End IsSpecialAsset_test_001");
}

/**
 * 测试目的：验证IsSpecialAsset方法识别另一个方向的特殊资产
 * 测试场景：照片高>宽，LCD宽>高，方向不一致
 * 预期结果：返回true，识别为特殊资产
 */
HWTEST_F(MediaLibraryLcdSizeTaskTest, IsSpecialAsset_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("Begin IsSpecialAsset_test_002");
    auto task = std::make_shared<MediaLcdSizeTask>();
    ASSERT_NE(task, nullptr);
    LcdAssetInfo assetInfo;
    assetInfo.photoWidth = TEST_WIDTH_1000;
    assetInfo.photoHeight = TEST_HEIGHT_2000;
    assetInfo.lcdSize = "2000:1000";
    bool result = task->IsSpecialAsset(assetInfo);
    EXPECT_EQ(result, true);
    EXPECT_EQ(assetInfo.lcdWidth, TEST_WIDTH_2000);
    EXPECT_EQ(assetInfo.lcdHeight, TEST_HEIGHT_1000);
    MEDIA_INFO_LOG("End IsSpecialAsset_test_002");
}

/**
 * 测试目的：验证IsSpecialAsset方法识别非特殊资产
 * 测试场景：照片宽高与LCD宽高方向一致
 * 预期结果：返回false
 */
HWTEST_F(MediaLibraryLcdSizeTaskTest, IsSpecialAsset_test_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("Begin IsSpecialAsset_test_003");
    auto task = std::make_shared<MediaLcdSizeTask>();
    ASSERT_NE(task, nullptr);
    LcdAssetInfo assetInfo;
    assetInfo.photoWidth = TEST_WIDTH_2000;
    assetInfo.photoHeight = TEST_HEIGHT_1000;
    assetInfo.lcdSize = "2000:1000";
    bool result = task->IsSpecialAsset(assetInfo);
    EXPECT_EQ(result, false);
    MEDIA_INFO_LOG("End IsSpecialAsset_test_003");
}

/**
 * 测试目的：验证IsSpecialAsset方法处理空LCD尺寸时返回false
 * 测试场景：LCD尺寸为空字符串
 * 预期结果：返回false
 */
HWTEST_F(MediaLibraryLcdSizeTaskTest, IsSpecialAsset_test_004, TestSize.Level1)
{
    MEDIA_INFO_LOG("Begin IsSpecialAsset_test_004");
    auto task = std::make_shared<MediaLcdSizeTask>();
    ASSERT_NE(task, nullptr);
    LcdAssetInfo assetInfo;
    assetInfo.photoWidth = TEST_WIDTH_2000;
    assetInfo.photoHeight = TEST_HEIGHT_1000;
    assetInfo.lcdSize = "";
    bool result = task->IsSpecialAsset(assetInfo);
    EXPECT_EQ(result, false);
    MEDIA_INFO_LOG("End IsSpecialAsset_test_004");
}

/**
 * 测试目的：验证IsSpecialAsset方法处理无效宽高时返回false
 * 测试场景：照片宽度为0
 * 预期结果：返回false
 */
HWTEST_F(MediaLibraryLcdSizeTaskTest, IsSpecialAsset_test_005, TestSize.Level1)
{
    MEDIA_INFO_LOG("Begin IsSpecialAsset_test_005");
    auto task = std::make_shared<MediaLcdSizeTask>();
    ASSERT_NE(task, nullptr);
    LcdAssetInfo assetInfo;
    assetInfo.photoWidth = 0;
    assetInfo.photoHeight = TEST_HEIGHT_1000;
    assetInfo.lcdSize = "1000:2000";
    bool result = task->IsSpecialAsset(assetInfo);
    EXPECT_EQ(result, false);
    MEDIA_INFO_LOG("End IsSpecialAsset_test_005");
}

/**
 * 测试目的：验证IsSpecialAsset方法处理LCD宽高无效时返回false
 * 测试场景：LCD高度为0
 * 预期结果：返回false
 */
HWTEST_F(MediaLibraryLcdSizeTaskTest, IsSpecialAsset_test_006, TestSize.Level1)
{
    MEDIA_INFO_LOG("Begin IsSpecialAsset_test_006");
    auto task = std::make_shared<MediaLcdSizeTask>();
    ASSERT_NE(task, nullptr);
    LcdAssetInfo assetInfo;
    assetInfo.photoWidth = TEST_WIDTH_2000;
    assetInfo.photoHeight = TEST_HEIGHT_1000;
    assetInfo.lcdSize = "1000:0";
    bool result = task->IsSpecialAsset(assetInfo);
    EXPECT_EQ(result, false);
    MEDIA_INFO_LOG("End IsSpecialAsset_test_006");
}

/**
 * 测试目的：验证IsSpecialAsset方法处理负值宽高
 * 测试场景：照片宽度为负值
 * 预期结果：返回false
 */
HWTEST_F(MediaLibraryLcdSizeTaskTest, IsSpecialAsset_test_007, TestSize.Level1)
{
    MEDIA_INFO_LOG("Begin IsSpecialAsset_test_007");
    auto task = std::make_shared<MediaLcdSizeTask>();
    ASSERT_NE(task, nullptr);
    LcdAssetInfo assetInfo;
    assetInfo.photoWidth = -1;
    assetInfo.photoHeight = TEST_HEIGHT_1000;
    assetInfo.lcdSize = "1000:2000";
    bool result = task->IsSpecialAsset(assetInfo);
    EXPECT_EQ(result, false);
    MEDIA_INFO_LOG("End IsSpecialAsset_test_007");
}

/**
 * 测试目的：验证IsSpecialAsset方法处理所有值都有效的非特殊情况
 * 测试场景：宽高方向一致，但所有值有效
 * 预期结果：返回false，因为不是特殊资产
 */
HWTEST_F(MediaLibraryLcdSizeTaskTest, IsSpecialAsset_test_008, TestSize.Level1)
{
    MEDIA_INFO_LOG("Begin IsSpecialAsset_test_008");
    auto task = std::make_shared<MediaLcdSizeTask>();
    ASSERT_NE(task, nullptr);
    LcdAssetInfo assetInfo;
    assetInfo.photoWidth = TEST_WIDTH_1000;
    assetInfo.photoHeight = TEST_HEIGHT_1000;
    assetInfo.lcdSize = "1000:1000";
    bool result = task->IsSpecialAsset(assetInfo);
    EXPECT_EQ(result, false);
    MEDIA_INFO_LOG("End IsSpecialAsset_test_008");
}

/**
 * 测试目的：验证QueryLcdAssets方法能够查询到LCD资产
 * 测试场景：数据库中有符合条件的资产数据
 * 预期结果：返回E_OK，lcdAssetInfos不为空
 */
HWTEST_F(MediaLibraryLcdSizeTaskTest, QueryLcdAssets_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("Begin QueryLcdAssets_test_001");
    auto task = std::make_shared<MediaLcdSizeTask>();
    ASSERT_NE(task, nullptr);
    vector<LcdAssetInfo> lcdAssetInfos;
    int32_t ret = task->QueryLcdAssets(0, lcdAssetInfos);
    EXPECT_EQ(ret, E_OK);
    EXPECT_GT(lcdAssetInfos.size(), 0);
    MEDIA_INFO_LOG("End QueryLcdAssets_test_001");
}

/**
 * 测试目的：验证QueryLcdAssets方法返回正确的资产信息
 * 测试场景：查询结果包含正确的fileId、宽高、LCD尺寸
 * 预期结果：资产信息字段正确
 */
HWTEST_F(MediaLibraryLcdSizeTaskTest, QueryLcdAssets_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("Begin QueryLcdAssets_test_002");
    auto task = std::make_shared<MediaLcdSizeTask>();
    ASSERT_NE(task, nullptr);
    vector<LcdAssetInfo> lcdAssetInfos;
    int32_t ret = task->QueryLcdAssets(0, lcdAssetInfos);
    EXPECT_EQ(ret, E_OK);
    if (!lcdAssetInfos.empty()) {
        bool foundTestFile1 = false;
        for (const auto &info : lcdAssetInfos) {
            if (info.fileId == static_cast<int32_t>(g_testFileId1)) {
                foundTestFile1 = true;
                EXPECT_EQ(info.photoWidth, TEST_WIDTH_1000);
                EXPECT_EQ(info.photoHeight, TEST_HEIGHT_2000);
                EXPECT_EQ(info.lcdSize, "1000:2000");
                break;
            }
        }
        EXPECT_TRUE(foundTestFile1);
    }
    MEDIA_INFO_LOG("End QueryLcdAssets_test_002");
}

/**
 * 测试目的：验证QueryLcdAssets方法处理指定startFileId
 * 测试场景：从指定fileId开始查询
 * 预期结果：返回fileId大于startFileId的数据
 */
HWTEST_F(MediaLibraryLcdSizeTaskTest, QueryLcdAssets_test_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("Begin QueryLcdAssets_test_003");
    auto task = std::make_shared<MediaLcdSizeTask>();
    ASSERT_NE(task, nullptr);
    vector<LcdAssetInfo> lcdAssetInfos;
    int32_t startFileId = static_cast<int32_t>(g_testFileId1);
    int32_t ret = task->QueryLcdAssets(startFileId, lcdAssetInfos);
    EXPECT_EQ(ret, E_OK);
    for (const auto &info : lcdAssetInfos) {
        EXPECT_GT(info.fileId, startFileId);
    }
    MEDIA_INFO_LOG("End QueryLcdAssets_test_003");
}

/**
 * 测试目的：验证UpdateDirtyStatus方法成功更新脏状态
 * 测试场景：传入有效的fileIds列表
 * 预期结果：返回大于0的updatedRows
 */
HWTEST_F(MediaLibraryLcdSizeTaskTest, UpdateDirtyStatus_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("Begin UpdateDirtyStatus_test_001");
    auto task = std::make_shared<MediaLcdSizeTask>();
    ASSERT_NE(task, nullptr);
    vector<string> fileIds;
    fileIds.push_back(to_string(g_testFileId1));
    int32_t ret = task->UpdateDirtyStatus(fileIds);
    EXPECT_GT(ret, 0);
    MEDIA_INFO_LOG("End UpdateDirtyStatus_test_001");
}

/**
 * 测试目的：验证UpdateDirtyStatus方法处理空列表时返回E_ERR
 * 测试场景：传入空的fileIds列表
 * 预期结果：返回E_ERR
 */
HWTEST_F(MediaLibraryLcdSizeTaskTest, UpdateDirtyStatus_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("Begin UpdateDirtyStatus_test_002");
    auto task = std::make_shared<MediaLcdSizeTask>();
    ASSERT_NE(task, nullptr);
    vector<string> fileIds;
    int32_t ret = task->UpdateDirtyStatus(fileIds);
    EXPECT_EQ(ret, E_ERR);
    MEDIA_INFO_LOG("End UpdateDirtyStatus_test_002");
}

/**
 * 测试目的：验证UpdateDirtyStatus方法更新多个fileId
 * 测试场景：传入多个fileIds
 * 预期结果：返回正确的updatedRows数量
 */
HWTEST_F(MediaLibraryLcdSizeTaskTest, UpdateDirtyStatus_test_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("Begin UpdateDirtyStatus_test_003");
    auto task = std::make_shared<MediaLcdSizeTask>();
    ASSERT_NE(task, nullptr);
    vector<string> fileIds;
    fileIds.push_back(to_string(g_testFileId1));
    fileIds.push_back(to_string(g_testFileId2));
    int32_t ret = task->UpdateDirtyStatus(fileIds);
    constexpr int32_t COUNT_TWO = 2;
    EXPECT_GE(ret, COUNT_TWO);
    MEDIA_INFO_LOG("End UpdateDirtyStatus_test_003");
}

/**
 * 测试目的：验证GetCursorStatus方法获取默认cursor值
 * 测试场景：首次调用，无预设值
 * 预期结果：返回CURSOR_INITIAL(0)或CURSOR_COMPLETED(-1)
 */
HWTEST_F(MediaLibraryLcdSizeTaskTest, GetCursorStatus_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("Begin GetCursorStatus_test_001");
    auto task = std::make_shared<MediaLcdSizeTask>();
    ASSERT_NE(task, nullptr);
    int32_t cursor = task->GetCursorStatus();
    EXPECT_TRUE(cursor == 0 || cursor == -1);
    MEDIA_INFO_LOG("End GetCursorStatus_test_001");
}

/**
 * 测试目的：验证SetCursorStatus方法能够设置cursor值
 * 测试场景：设置cursor为特定值后获取验证
 * 预期结果：设置的值与获取的值一致
 */
HWTEST_F(MediaLibraryLcdSizeTaskTest, SetCursorStatus_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("Begin SetCursorStatus_test_001");
    auto task = std::make_shared<MediaLcdSizeTask>();
    ASSERT_NE(task, nullptr);
    int32_t testCursor = 100;
    task->SetCursorStatus(testCursor);
    int32_t cursor = task->GetCursorStatus();
    EXPECT_EQ(cursor, testCursor);
    MEDIA_INFO_LOG("End SetCursorStatus_test_001");
}

/**
 * 测试目的：验证SetCursorStatus方法设置完成状态CURSOR_COMPLETED
 * 测试场景：设置cursor为-1表示任务完成
 * 预期结果：cursor值为-1
 */
HWTEST_F(MediaLibraryLcdSizeTaskTest, SetCursorStatus_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("Begin SetCursorStatus_test_002");
    auto task = std::make_shared<MediaLcdSizeTask>();
    ASSERT_NE(task, nullptr);
    int32_t testCursor = -1;
    task->SetCursorStatus(testCursor);
    int32_t cursor = task->GetCursorStatus();
    EXPECT_EQ(cursor, testCursor);
    MEDIA_INFO_LOG("End SetCursorStatus_test_002");
}

/**
 * 测试目的：验证整体流程：查询特殊资产并更新脏状态
 * 测试场景：完整流程测试
 * 预期结果：特殊资产被正确识别并更新
 */
HWTEST_F(MediaLibraryLcdSizeTaskTest, Integration_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("Begin Integration_test_001");
    auto task = std::make_shared<MediaLcdSizeTask>();
    ASSERT_NE(task, nullptr);
    vector<LcdAssetInfo> lcdAssetInfos;
    int32_t ret = task->QueryLcdAssets(0, lcdAssetInfos);
    EXPECT_EQ(ret, E_OK);

    vector<string> specialFileIds;
    for (auto &info : lcdAssetInfos) {
        if (task->IsSpecialAsset(info)) {
            specialFileIds.push_back(to_string(info.fileId));
            MEDIA_INFO_LOG("Special asset: fileId=%{public}d, photoW=%{public}d, photoH=%{public}d, "
                "lcdW=%{public}d, lcdH=%{public}d",
                info.fileId, info.photoWidth, info.photoHeight, info.lcdWidth, info.lcdHeight);
        }
    }

    if (!specialFileIds.empty()) {
        int32_t updateRet = task->UpdateDirtyStatus(specialFileIds);
        EXPECT_GT(updateRet, 0);
    }
    MEDIA_INFO_LOG("End Integration_test_001");
}
}  // namespace OHOS::Media::Background
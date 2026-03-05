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

#include "notification_helper_test.h"
#include "medialibrary_errno.h"
#include "photo_album.h"
#include "photo_album_column.h"
#include "fetch_result.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_command.h"
#include "rdb_predicates.h"
#include "result_set_utils.h"
#include "rdb_utils.h"
#include "datashare_result_set.h"
#include "userfile_manager_types.h"
#include <memory>
#include <thread>
#include <vector>
#include <atomic>
#include <chrono>
#include <string>
#include <climits>

using namespace testing::ext;
using namespace OHOS::Media::NotificationHelper;
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;
using OHOS::DataShare::DataShareValuesBucket;
using OHOS::DataShare::DataSharePredicates;
using std::string;
using std::vector;
using std::shared_ptr;
using std::make_shared;
using std::make_unique;
using std::unique_ptr;

namespace OHOS {
namespace Media {

// Static variables for database tests
static shared_ptr<MediaLibraryRdbStore> g_rdbStore;
const std::string URI_CREATE_PHOTO_ALBUM = MEDIALIBRARY_DATA_URI + "/" + CONST_PHOTO_ALBUM_OPRN + "/" + OPRN_CREATE;
const std::string URI_UPDATE_PHOTO_ALBUM = MEDIALIBRARY_DATA_URI + "/" + CONST_PHOTO_ALBUM_OPRN + "/" + OPRN_UPDATE;

// Helper function to check column values
inline void CheckColumn(shared_ptr<NativeRdb::ResultSet> &resultSet, const string &column,
    ResultSetDataType type, const variant<int32_t, string, int64_t, double> &expected)
{
    EXPECT_EQ(ResultSetUtils::GetValFromColumn(column, resultSet, type), expected);
}

// Helper function to create photo album
inline int32_t CreatePhotoAlbum(const string &albumName)
{
    DataShareValuesBucket values;
    values.Put(PhotoAlbumColumns::ALBUM_NAME, albumName);
    Uri uri(URI_CREATE_PHOTO_ALBUM);
    MediaLibraryCommand cmd(uri);
    return MediaLibraryDataManager::GetInstance()->Insert(cmd, values);
}

// Helper function to update photo album
inline int32_t UpdatePhotoAlbum(const DataShareValuesBucket &values, const DataSharePredicates &predicates)
{
    Uri uri(URI_UPDATE_PHOTO_ALBUM);
    MediaLibraryCommand cmd(uri, OperationType::UPDATE);
    return MediaLibraryDataManager::GetInstance()->Update(cmd, values, predicates);
}

void NotificationHelperTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("NotificationHelperTest SetUpTestCase");
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
}

void NotificationHelperTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("NotificationHelperTest TearDownTestCase");
}

void NotificationHelperTest::SetUp()
{
    MEDIA_INFO_LOG("NotificationHelperTest SetUp");
}

void NotificationHelperTest::TearDown()
{
    MEDIA_INFO_LOG("NotificationHelperTest TearDown");
}

/**
 * @tc.number    : NotificationHelper_Callback_Data_test_001
 * @tc.name      : Callback data: Verify AlbumChangeData content
 * @tc.desc      : Verify callback receives correct AlbumChangeData content
 */
HWTEST_F(NotificationHelperTest, NotificationHelper_Callback_Data_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("NotificationHelper_Callback_Data_test_001 enter");

    auto callback = std::make_shared<MockPhotoAlbumChangeCallback>();
    ASSERT_NE(callback, nullptr);

    AlbumChangeInfos testInfo;
    testInfo.type = NotifyChangeType::NOTIFY_CHANGE_ADD;

    AlbumChangeData data1;
    data1.version = 100;
    testInfo.albumChangeDatas.push_back(data1);

    AlbumChangeData data2;
    data2.version = 200;
    testInfo.albumChangeDatas.push_back(data2);

    callback->OnChange(testInfo);

    AlbumChangeInfos received = callback->GetLastInfo();
    EXPECT_EQ(received.albumChangeDatas.size(), 2);
    EXPECT_EQ(received.albumChangeDatas[0].version, 100);
    EXPECT_EQ(received.albumChangeDatas[1].version, 200);

    MEDIA_INFO_LOG("NotificationHelper_Callback_Data_test_001 exit");
}

/**
 * @tc.number    : NotificationHelper_Callback_Data_test_002
 * @tc.name      : Callback data: Verify AlbumChangeInfo pointers
 * @tc.desc      : Verify AlbumChangeInfo shared pointers are handled correctly
 */
HWTEST_F(NotificationHelperTest, NotificationHelper_Callback_Data_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("NotificationHelper_Callback_Data_test_002 enter");

    auto callback = std::make_shared<MockPhotoAlbumChangeCallback>();
    ASSERT_NE(callback, nullptr);

    AlbumChangeInfos testInfo;
    testInfo.type = NotifyChangeType::NOTIFY_CHANGE_UPDATE;

    AlbumChangeData changeData;
    // albumBeforeChange and albumAfterChange are nullptr by default
    changeData.version = 500;
    testInfo.albumChangeDatas.push_back(changeData);

    callback->OnChange(testInfo);

    AlbumChangeInfos received = callback->GetLastInfo();
    EXPECT_EQ(received.albumChangeDatas.size(), 1);
    EXPECT_EQ(received.albumChangeDatas[0].version, 500);
    EXPECT_EQ(received.albumChangeDatas[0].albumBeforeChange, nullptr);
    EXPECT_EQ(received.albumChangeDatas[0].albumAfterChange, nullptr);

    MEDIA_INFO_LOG("NotificationHelper_Callback_Data_test_002 exit");
}

/**
 * @tc.number    : NotificationHelper_RegisterPhotoAlbumCallback_test_007
 * @tc.name      : RegisterPhotoAlbumCallback: Register with different callback types
 * @tc.desc      : Verify different callback instances can be registered
 */
HWTEST_F(NotificationHelperTest, NotificationHelper_RegisterPhotoAlbumCallback_test_007, TestSize.Level1)
{
    MEDIA_INFO_LOG("NotificationHelper_RegisterPhotoAlbumCallback_test_007 enter");

    auto callback1 = std::make_shared<MockPhotoAlbumChangeCallback>();
    auto callback2 = std::make_shared<MockPhotoAlbumChangeCallback>();
    auto callback3 = std::make_shared<MockPhotoAlbumChangeCallback>();

    ASSERT_NE(callback1, nullptr);
    ASSERT_NE(callback2, nullptr);
    ASSERT_NE(callback3, nullptr);

    // Verify they are different instances
    EXPECT_NE(callback1.get(), callback2.get());
    EXPECT_NE(callback2.get(), callback3.get());

    // Register all
    int32_t ret1 = NotificationHelper::RegisterPhotoAlbumCallback(callback1);
    int32_t ret2 = NotificationHelper::RegisterPhotoAlbumCallback(callback2);
    int32_t ret3 = NotificationHelper::RegisterPhotoAlbumCallback(callback3);

    EXPECT_EQ(ret1, 0);
    EXPECT_EQ(ret2, 0);
    EXPECT_EQ(ret3, 0);

    // Unregister all
    NotificationHelper::unRegisterPhotoAlbumCallback(callback1);
    NotificationHelper::unRegisterPhotoAlbumCallback(callback2);
    NotificationHelper::unRegisterPhotoAlbumCallback(callback3);

    MEDIA_INFO_LOG("NotificationHelper_RegisterPhotoAlbumCallback_test_007 exit");
}

/**
 * @tc.number    : NotificationHelper_unRegisterPhotoAlbumCallback_test_005
 * @tc.name      : unRegisterPhotoAlbumCallback: Unregister after multiple registers
 * @tc.desc      : Verify unregister works after same callback registered multiple times
 */
HWTEST_F(NotificationHelperTest, NotificationHelper_unRegisterPhotoAlbumCallback_test_005, TestSize.Level1)
{
    MEDIA_INFO_LOG("NotificationHelper_unRegisterPhotoAlbumCallback_test_005 enter");

    auto callback = std::make_shared<MockPhotoAlbumChangeCallback>();
    ASSERT_NE(callback, nullptr);

    // Register same callback multiple times
    NotificationHelper::RegisterPhotoAlbumCallback(callback);
    NotificationHelper::RegisterPhotoAlbumCallback(callback);
    NotificationHelper::RegisterPhotoAlbumCallback(callback);

    // Unregister once should remove one instance
    int32_t ret = NotificationHelper::unRegisterPhotoAlbumCallback(callback);
    EXPECT_EQ(ret, 0);

    // Should still be registered (other instances)
    ret = NotificationHelper::unRegisterPhotoAlbumCallback(callback);
    EXPECT_EQ(ret, 0);

    ret = NotificationHelper::unRegisterPhotoAlbumCallback(callback);
    EXPECT_EQ(ret, 0);

    // Now should not be registered
    ret = NotificationHelper::unRegisterPhotoAlbumCallback(callback);
    EXPECT_EQ(ret, -1);

    MEDIA_INFO_LOG("NotificationHelper_unRegisterPhotoAlbumCallback_test_005 exit");
}

/**
 * @tc.number    : NotificationHelper_Callback_OnChange_test_008
 * @tc.name      : PhotoAlbumChangeCallback: OnChange with all change types
 * @tc.desc      : Verify OnChange handles all NotifyChangeType values
 */
HWTEST_F(NotificationHelperTest, NotificationHelper_Callback_OnChange_test_008, TestSize.Level1)
{
    MEDIA_INFO_LOG("NotificationHelper_Callback_OnChange_test_008 enter");

    auto callback = std::make_shared<MockPhotoAlbumChangeCallback>();
    ASSERT_NE(callback, nullptr);

    // Test all change types
    std::vector<NotifyChangeType> changeTypes = {
        NotifyChangeType::NOTIFY_CHANGE_ADD,
        NotifyChangeType::NOTIFY_CHANGE_UPDATE,
        NotifyChangeType::NOTIFY_CHANGE_REMOVE,
        NotifyChangeType::NOTIFY_CHANGE_INVALID
    };

    for (auto type : changeTypes) {
        AlbumChangeInfos testInfo;
        testInfo.type = type;
        callback->OnChange(testInfo);
    }

    EXPECT_EQ(callback->GetCallCount(), 4);
    EXPECT_EQ(callback->GetLastChangeType(), NotifyChangeType::NOTIFY_CHANGE_INVALID);

    MEDIA_INFO_LOG("NotificationHelper_Callback_OnChange_test_008 exit");
}

/**
 * @tc.number    : NotificationHelper_Edge_Case_test_009
 * @tc.name      : Edge case: Register null then valid callback
 * @tc.desc      : Verify null callback rejection doesn't affect valid registration
 */
HWTEST_F(NotificationHelperTest, NotificationHelper_Edge_Case_test_009, TestSize.Level1)
{
    MEDIA_INFO_LOG("NotificationHelper_Edge_Case_test_009 enter");

    // Try to register null
    std::shared_ptr<PhotoAlbumChangeCallback> nullCallback = nullptr;
    int32_t ret = NotificationHelper::RegisterPhotoAlbumCallback(nullCallback);
    EXPECT_EQ(ret, -1);

    // Register valid callback should still work
    auto validCallback = std::make_shared<MockPhotoAlbumChangeCallback>();
    ret = NotificationHelper::RegisterPhotoAlbumCallback(validCallback);
    EXPECT_EQ(ret, 0);

    NotificationHelper::unRegisterPhotoAlbumCallback(validCallback);

    MEDIA_INFO_LOG("NotificationHelper_Edge_Case_test_009 exit");
}

/**
 * @tc.number    : NotificationHelper_Edge_Case_test_010
 * @tc.name      : Edge case: Unregister null then valid callback
 * @tc.desc      : Verify null callback unregister rejection doesn't affect valid unregister
 */
HWTEST_F(NotificationHelperTest, NotificationHelper_Edge_Case_test_010, TestSize.Level1)
{
    MEDIA_INFO_LOG("NotificationHelper_Edge_Case_test_010 enter");

    // Try to unregister null
    std::shared_ptr<PhotoAlbumChangeCallback> nullCallback = nullptr;
    int32_t ret = NotificationHelper::unRegisterPhotoAlbumCallback(nullCallback);
    EXPECT_EQ(ret, -1);

    // Register and unregister valid callback should work
    auto validCallback = std::make_shared<MockPhotoAlbumChangeCallback>();
    ret = NotificationHelper::RegisterPhotoAlbumCallback(validCallback);
    EXPECT_EQ(ret, 0);

    ret = NotificationHelper::unRegisterPhotoAlbumCallback(validCallback);
    EXPECT_EQ(ret, 0);

    MEDIA_INFO_LOG("NotificationHelper_Edge_Case_test_010 exit");
}

/**
 * @tc.number    : NotificationHelper_Callback_Multiple_test_002
 * @tc.name      : Multiple callbacks: Verify independent callback state
 * @tc.desc      : Verify multiple callbacks maintain independent state
 */
HWTEST_F(NotificationHelperTest, NotificationHelper_Callback_Multiple_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("NotificationHelper_Callback_Multiple_test_002 enter");

    auto callback1 = std::make_shared<MockPhotoAlbumChangeCallback>();
    auto callback2 = std::make_shared<MockPhotoAlbumChangeCallback>();

    ASSERT_NE(callback1, nullptr);
    ASSERT_NE(callback2, nullptr);

    // Register both
    NotificationHelper::RegisterPhotoAlbumCallback(callback1);
    NotificationHelper::RegisterPhotoAlbumCallback(callback2);

    // Call OnChange on first callback only
    AlbumChangeInfos testInfo;
    testInfo.type = NotifyChangeType::NOTIFY_CHANGE_ADD;
    callback1->OnChange(testInfo);

    // Verify only first callback was called
    EXPECT_EQ(callback1->GetCallCount(), 1);
    EXPECT_EQ(callback2->GetCallCount(), 0);

    // Clean up
    NotificationHelper::unRegisterPhotoAlbumCallback(callback1);
    NotificationHelper::unRegisterPhotoAlbumCallback(callback2);

    MEDIA_INFO_LOG("NotificationHelper_Callback_Multiple_test_002 exit");
}

/**
 * @tc.number    : NotificationHelper_Callback_Reset_test_002
 * @tc.name      : Mock callback: Reset between operations
 * @tc.desc      : Verify Reset works correctly between multiple operations
 */
HWTEST_F(NotificationHelperTest, NotificationHelper_Callback_Reset_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("NotificationHelper_Callback_Reset_test_002 enter");

    auto callback = std::make_shared<MockPhotoAlbumChangeCallback>();
    ASSERT_NE(callback, nullptr);

    // First set of operations
    AlbumChangeInfos testInfo1;
    testInfo1.type = NotifyChangeType::NOTIFY_CHANGE_ADD;
    callback->OnChange(testInfo1);
    EXPECT_EQ(callback->GetCallCount(), 1);

    // Reset
    callback->Reset();
    EXPECT_EQ(callback->GetCallCount(), 0);

    // Second set of operations
    AlbumChangeInfos testInfo2;
    testInfo2.type = NotifyChangeType::NOTIFY_CHANGE_UPDATE;
    callback->OnChange(testInfo2);
    EXPECT_EQ(callback->GetCallCount(), 1);
    EXPECT_EQ(callback->GetLastChangeType(), NotifyChangeType::NOTIFY_CHANGE_UPDATE);

    MEDIA_INFO_LOG("NotificationHelper_Callback_Reset_test_002 exit");
}

/**
 * @tc.number    : NotificationHelper_Edge_Case_test_011
 * @tc.name      : Edge case: Very large AlbumChangeDatas vector
 * @tc.desc      : Verify callback handles large number of AlbumChangeData
 */
HWTEST_F(NotificationHelperTest, NotificationHelper_Edge_Case_test_011, TestSize.Level1)
{
    MEDIA_INFO_LOG("NotificationHelper_Edge_Case_test_011 enter");

    auto callback = std::make_shared<MockPhotoAlbumChangeCallback>();
    ASSERT_NE(callback, nullptr);

    AlbumChangeInfos testInfo;
    testInfo.type = NotifyChangeType::NOTIFY_CHANGE_UPDATE;

    const int32_t largeCount = 1000;
    for (int32_t i = 0; i < largeCount; i++) {
        AlbumChangeData changeData;
        changeData.version = i;
        testInfo.albumChangeDatas.push_back(changeData);
    }

    int32_t ret = callback->OnChange(testInfo);
    EXPECT_EQ(ret, 0);

    AlbumChangeInfos received = callback->GetLastInfo();
    EXPECT_EQ(received.albumChangeDatas.size(), largeCount);

    MEDIA_INFO_LOG("NotificationHelper_Edge_Case_test_011 exit");
}

/**
 * @tc.number    : NotificationHelper_Edge_Case_test_012
 * @tc.name      : Edge case: Register/unregister interleaved with operations
 * @tc.desc      : Verify register/unregister works while callbacks are being used
 */
HWTEST_F(NotificationHelperTest, NotificationHelper_Edge_Case_test_012, TestSize.Level1)
{
    MEDIA_INFO_LOG("NotificationHelper_Edge_Case_test_012 enter");

    auto callback1 = std::make_shared<MockPhotoAlbumChangeCallback>();
    auto callback2 = std::make_shared<MockPhotoAlbumChangeCallback>();

    NotificationHelper::RegisterPhotoAlbumCallback(callback1);

    // Use callback1
    AlbumChangeInfos testInfo;
    testInfo.type = NotifyChangeType::NOTIFY_CHANGE_ADD;
    callback1->OnChange(testInfo);

    // Register callback2
    NotificationHelper::RegisterPhotoAlbumCallback(callback2);

    // Unregister callback1
    int32_t ret = NotificationHelper::unRegisterPhotoAlbumCallback(callback1);
    EXPECT_EQ(ret, 0);

    // Use callback2
    callback2->OnChange(testInfo);

    // Unregister callback2
    ret = NotificationHelper::unRegisterPhotoAlbumCallback(callback2);
    EXPECT_EQ(ret, 0);

    MEDIA_INFO_LOG("NotificationHelper_Edge_Case_test_012 exit");
}

/**
 * @tc.number    : NotificationHelper_PhotoAlbum_SetGet_Test_001
 * @tc.name      : PhotoAlbum SetSceneId and GetSceneId, SetShareType and GetShareType test
 * @tc.desc      : Verify SetSceneId, GetSceneId, SetShareType, and GetShareType functions work correctly
 */
HWTEST_F(NotificationHelperTest, NotificationHelper_PhotoAlbum_SetGet_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("NotificationHelper_PhotoAlbum_SetGet_Test_001 enter");

    PhotoAlbum photoAlbum;

    const int32_t TEST_ALBUM_ID = 1;
    photoAlbum.SetAlbumId(TEST_ALBUM_ID);
    EXPECT_EQ(photoAlbum.GetAlbumId(), TEST_ALBUM_ID);

    photoAlbum.SetPhotoAlbumType(PhotoAlbumType::USER);
    EXPECT_EQ(photoAlbum.GetPhotoAlbumType(), PhotoAlbumType::USER);

    photoAlbum.SetPhotoAlbumSubType(PhotoAlbumSubType::USER_GENERIC);
    EXPECT_EQ(photoAlbum.GetPhotoAlbumSubType(), PhotoAlbumSubType::USER_GENERIC);

    const string TEST_URI = "file://media/album/1";
    photoAlbum.SetAlbumUri(TEST_URI);
    EXPECT_EQ(photoAlbum.GetAlbumUri(), TEST_URI);

    const string TEST_ALBUM_NAME = "test";
    photoAlbum.SetAlbumName(TEST_ALBUM_NAME);
    EXPECT_EQ(photoAlbum.GetAlbumName(), TEST_ALBUM_NAME);

    const string TEST_COVERURI = TEST_URI;
    photoAlbum.SetCoverUri(TEST_COVERURI);
    EXPECT_EQ(photoAlbum.GetCoverUri(), TEST_COVERURI);

    const int32_t TEST_COUNT = 1;
    photoAlbum.SetCount(TEST_COUNT);
    EXPECT_EQ(photoAlbum.GetCount(), TEST_COUNT);

    const string TEST_RELATIVE_PATH = "Camera";
    photoAlbum.SetRelativePath(TEST_RELATIVE_PATH);
    EXPECT_EQ(photoAlbum.GetRelativePath(), TEST_RELATIVE_PATH);

    const int64_t CHANGE_TIME = 1;
    photoAlbum.SetChangeTime(CHANGE_TIME);
    EXPECT_EQ(photoAlbum.GetChangeTime(), CHANGE_TIME);

    photoAlbum.SetResultNapiType(ResultNapiType::TYPE_USERFILE_MGR);
    EXPECT_EQ(photoAlbum.GetResultNapiType(), ResultNapiType::TYPE_USERFILE_MGR);

    photoAlbum.SetHidden(TEST_ALBUM_ID);
    EXPECT_EQ(photoAlbum.GetHidden(), TEST_ALBUM_ID);

    const int32_t TEST_SCENE_ID = 100;
    photoAlbum.SetSceneId(TEST_SCENE_ID);
    EXPECT_EQ(photoAlbum.GetSceneId(), TEST_SCENE_ID);

    const int32_t TEST_SHARE_TYPE = 200;
    photoAlbum.SetShareType(TEST_SHARE_TYPE);
    EXPECT_EQ(photoAlbum.GetShareType(), TEST_SHARE_TYPE);

    MEDIA_INFO_LOG("NotificationHelper_PhotoAlbum_SetGet_Test_001 exit");
}

/**
 * @tc.number    : NotificationHelper_PhotoAlbum_SetGet_Test_002
 * @tc.name      : PhotoAlbum SetSceneId and GetSceneId test
 * @tc.desc      : Verify SetSceneId and GetSceneId functions work correctly with various values
 */
HWTEST_F(NotificationHelperTest, NotificationHelper_PhotoAlbum_SetGet_Test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("NotificationHelper_PhotoAlbum_SetGet_Test_002 enter");

    PhotoAlbum photoAlbum;

    const int32_t TEST_SCENE_ID_1 = 0;
    photoAlbum.SetSceneId(TEST_SCENE_ID_1);
    EXPECT_EQ(photoAlbum.GetSceneId(), TEST_SCENE_ID_1);

    const int32_t TEST_SCENE_ID_2 = 100;
    photoAlbum.SetSceneId(TEST_SCENE_ID_2);
    EXPECT_EQ(photoAlbum.GetSceneId(), TEST_SCENE_ID_2);

    const int32_t TEST_SCENE_ID_3 = -1;
    photoAlbum.SetSceneId(TEST_SCENE_ID_3);
    EXPECT_EQ(photoAlbum.GetSceneId(), TEST_SCENE_ID_3);

    MEDIA_INFO_LOG("NotificationHelper_PhotoAlbum_SetGet_Test_002 exit");
}

/**
 * @tc.number    : NotificationHelper_PhotoAlbum_SetGet_Test_003
 * @tc.name      : PhotoAlbum SetShareType and GetShareType test
 * @tc.desc      : Verify SetShareType and GetShareType functions work correctly with various values
 */
HWTEST_F(NotificationHelperTest, NotificationHelper_PhotoAlbum_SetGet_Test_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("NotificationHelper_PhotoAlbum_SetGet_Test_003 enter");

    PhotoAlbum photoAlbum;

    const int32_t TEST_SHARE_TYPE_1 = 0;
    photoAlbum.SetShareType(TEST_SHARE_TYPE_1);
    EXPECT_EQ(photoAlbum.GetShareType(), TEST_SHARE_TYPE_1);

    const int32_t TEST_SHARE_TYPE_2 = 200;
    photoAlbum.SetShareType(TEST_SHARE_TYPE_2);
    EXPECT_EQ(photoAlbum.GetShareType(), TEST_SHARE_TYPE_2);

    const int32_t TEST_SHARE_TYPE_3 = -1;
    photoAlbum.SetShareType(TEST_SHARE_TYPE_3);
    EXPECT_EQ(photoAlbum.GetShareType(), TEST_SHARE_TYPE_3);

    MEDIA_INFO_LOG("NotificationHelper_PhotoAlbum_SetGet_Test_003 exit");
}

/**
 * @tc.number    : NotificationHelper_PhotoAlbum_SetGet_Test_004
 * @tc.name      : PhotoAlbum SetSceneId and SetShareType combined test
 * @tc.desc      : Verify SetSceneId and SetShareType can be used together
 */
HWTEST_F(NotificationHelperTest, NotificationHelper_PhotoAlbum_SetGet_Test_004, TestSize.Level1)
{
    MEDIA_INFO_LOG("NotificationHelper_PhotoAlbum_SetGet_Test_004 enter");

    PhotoAlbum photoAlbum;

    const int32_t TEST_SCENE_ID = 100;
    const int32_t TEST_SHARE_TYPE = 200;

    photoAlbum.SetSceneId(TEST_SCENE_ID);
    photoAlbum.SetShareType(TEST_SHARE_TYPE);

    EXPECT_EQ(photoAlbum.GetSceneId(), TEST_SCENE_ID);
    EXPECT_EQ(photoAlbum.GetShareType(), TEST_SHARE_TYPE);

    // Change values
    const int32_t TEST_SCENE_ID_2 = 300;
    const int32_t TEST_SHARE_TYPE_2 = 400;

    photoAlbum.SetSceneId(TEST_SCENE_ID_2);
    photoAlbum.SetShareType(TEST_SHARE_TYPE_2);

    EXPECT_EQ(photoAlbum.GetSceneId(), TEST_SCENE_ID_2);
    EXPECT_EQ(photoAlbum.GetShareType(), TEST_SHARE_TYPE_2);

    MEDIA_INFO_LOG("NotificationHelper_PhotoAlbum_SetGet_Test_004 exit");
}

/**
 * @tc.number    : NotificationHelper_PhotoAlbum_Database_Test_001
 * @tc.name      : PhotoAlbum database scene_id and share_type test
 * @tc.desc      : Test scene_id and share_type columns in PhotoAlbum table
 *                 1. Create album and verify default values
 *                 2. Update scene_id and share_type
 *                 3. Query and verify updated values
 */
HWTEST_F(NotificationHelperTest, NotificationHelper_PhotoAlbum_Database_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("NotificationHelper_PhotoAlbum_Database_Test_001 enter");

    if (g_rdbStore == nullptr) {
        MEDIA_WARN_LOG("g_rdbStore is nullptr, skipping database test");
        return;
    }

    const string albumName = "NotificationHelper_PhotoAlbum_Database_Test_001";
    int32_t albumId = CreatePhotoAlbum(albumName);
    ASSERT_GT(albumId, 0);

    // Query album and verify default values
    RdbPredicates predicates(PhotoAlbumColumns::TABLE);
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, to_string(albumId));

    const vector<string> columns = {
        PhotoAlbumColumns::ALBUM_ID,
        PhotoAlbumColumns::ALBUM_SCENE_ID,
        PhotoAlbumColumns::ALBUM_SHARE_TYPE,
    };

    auto resultSet = g_rdbStore->Query(predicates, columns);
    ASSERT_NE(resultSet, nullptr);
    int32_t count = -1;
    CHECK_AND_RETURN_LOG(resultSet->GetRowCount(count) == E_OK, "Failed to get count!");
    EXPECT_GT(count, 0);
    CHECK_AND_RETURN_LOG(resultSet->GoToFirstRow() == E_OK, "Failed to GoToFirstRow!");

    // Verify default values (should be 0)
    CheckColumn(resultSet, PhotoAlbumColumns::ALBUM_SCENE_ID, TYPE_INT32, 0);
    CheckColumn(resultSet, PhotoAlbumColumns::ALBUM_SHARE_TYPE, TYPE_INT32, 0);

    // Update scene_id and share_type
    const int32_t TEST_SCENE_ID = 100;
    const int32_t TEST_SHARE_TYPE = 200;

    DataShareValuesBucket values;
    values.Put(PhotoAlbumColumns::ALBUM_SCENE_ID, TEST_SCENE_ID);
    values.Put(PhotoAlbumColumns::ALBUM_SHARE_TYPE, TEST_SHARE_TYPE);

    DataSharePredicates updatePredicates;
    updatePredicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, albumId);
    EXPECT_EQ(UpdatePhotoAlbum(values, updatePredicates), 0);

    // Query again and verify updated values
    resultSet = g_rdbStore->Query(predicates, columns);
    ASSERT_NE(resultSet, nullptr);
    CHECK_AND_RETURN_LOG(resultSet->GoToFirstRow() == E_OK, "Failed to GoToFirstRow!");

    CheckColumn(resultSet, PhotoAlbumColumns::ALBUM_SCENE_ID, TYPE_INT32, TEST_SCENE_ID);
    CheckColumn(resultSet, PhotoAlbumColumns::ALBUM_SHARE_TYPE, TYPE_INT32, TEST_SHARE_TYPE);

    MEDIA_INFO_LOG("NotificationHelper_PhotoAlbum_Database_Test_001 exit");
}

/**
 * @tc.number    : NotificationHelper_PhotoAlbum_Database_Test_002
 * @tc.name      : PhotoAlbum FetchResult parsing test
 * @tc.desc      : Test scene_id and share_type with FetchResult parsing
 *                 1. Create album with scene_id and share_type
 *                 2. Query using FetchResult
 *                 3. Verify PhotoAlbum object has correct values
 */
HWTEST_F(NotificationHelperTest, NotificationHelper_PhotoAlbum_Database_Test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("NotificationHelper_PhotoAlbum_Database_Test_002 enter");

    if (g_rdbStore == nullptr) {
        MEDIA_WARN_LOG("g_rdbStore is nullptr, skipping database test");
        return;
    }

    const string albumName = "NotificationHelper_PhotoAlbum_Database_Test_002";
    int32_t albumId = CreatePhotoAlbum(albumName);
    ASSERT_GT(albumId, 0);

    // Update scene_id and share_type
    const int32_t TEST_SCENE_ID = 300;
    const int32_t TEST_SHARE_TYPE = 400;

    DataShareValuesBucket values;
    values.Put(PhotoAlbumColumns::ALBUM_SCENE_ID, TEST_SCENE_ID);
    values.Put(PhotoAlbumColumns::ALBUM_SHARE_TYPE, TEST_SHARE_TYPE);

    DataSharePredicates predicates;
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, albumId);
    EXPECT_EQ(UpdatePhotoAlbum(values, predicates), 0);

    // Query using FetchResult
    RdbPredicates queryPredicates(PhotoAlbumColumns::TABLE);
    queryPredicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, to_string(albumId));

    vector<string> queryColumns;
    auto resultSet = g_rdbStore->Query(queryPredicates, queryColumns);
    ASSERT_NE(resultSet, nullptr);

    // Use FetchResult to parse PhotoAlbum
    auto bridge = RdbDataShareAdapter::RdbUtils::ToResultSetBridge(resultSet);
    auto fetchResult = make_unique<FetchResult<PhotoAlbum>>(
        make_shared<DataShare::DataShareResultSet>(bridge));
    ASSERT_NE(fetchResult, nullptr);

    auto photoAlbum = fetchResult->GetFirstObject();
    ASSERT_NE(photoAlbum, nullptr);

    // Verify values are correctly parsed
    EXPECT_EQ(photoAlbum->GetSceneId(), TEST_SCENE_ID);
    EXPECT_EQ(photoAlbum->GetShareType(), TEST_SHARE_TYPE);

    MEDIA_INFO_LOG("NotificationHelper_PhotoAlbum_Database_Test_002 exit");
}

/**
 * @tc.number    : NotificationHelper_RegisterPhotoAlbumCallback_test_008
 * @tc.name      : RegisterPhotoAlbumCallback: Register callback with maximum boundary values
 * @tc.desc      : Verify system handles large number of callback registrations
 */
HWTEST_F(NotificationHelperTest, NotificationHelper_RegisterPhotoAlbumCallback_test_008, TestSize.Level1)
{
    MEDIA_INFO_LOG("NotificationHelper_RegisterPhotoAlbumCallback_test_008 enter");

    const int32_t MAX_CALLBACKS = 1000;
    std::vector<std::shared_ptr<MockPhotoAlbumChangeCallback>> callbacks;

    for (int32_t i = 0; i < MAX_CALLBACKS; i++) {
        auto callback = std::make_shared<MockPhotoAlbumChangeCallback>();
        int32_t ret = NotificationHelper::RegisterPhotoAlbumCallback(callback);
        EXPECT_EQ(ret, 0);
        callbacks.push_back(callback);
    }

    // Unregister all
    for (auto& callback : callbacks) {
        NotificationHelper::unRegisterPhotoAlbumCallback(callback);
    }

    MEDIA_INFO_LOG("NotificationHelper_RegisterPhotoAlbumCallback_test_008 exit");
}

/**
 * @tc.number    : NotificationHelper_RegisterPhotoAlbumCallback_test_009
 * @tc.name      : RegisterPhotoAlbumCallback: Register and verify callback persistence
 * @tc.desc      : Verify registered callback persists across multiple operations
 */
HWTEST_F(NotificationHelperTest, NotificationHelper_RegisterPhotoAlbumCallback_test_009, TestSize.Level1)
{
    MEDIA_INFO_LOG("NotificationHelper_RegisterPhotoAlbumCallback_test_009 enter");

    auto callback = std::make_shared<MockPhotoAlbumChangeCallback>();
    ASSERT_NE(callback, nullptr);

    int32_t ret = NotificationHelper::RegisterPhotoAlbumCallback(callback);
    EXPECT_EQ(ret, 0);

    // Verify callback is still registered after multiple operations
    AlbumChangeInfos testInfo;
    testInfo.type = NotifyChangeType::NOTIFY_CHANGE_UPDATE;
    callback->OnChange(testInfo);
    EXPECT_EQ(callback->GetCallCount(), 1);

    // Unregister
    ret = NotificationHelper::unRegisterPhotoAlbumCallback(callback);
    EXPECT_EQ(ret, 0);

    MEDIA_INFO_LOG("NotificationHelper_RegisterPhotoAlbumCallback_test_009 exit");
}

/**
 * @tc.number    : NotificationHelper_unRegisterPhotoAlbumCallback_test_006
 * @tc.name      : unRegisterPhotoAlbumCallback: Unregister from middle of list
 * @tc.desc      : Verify unregistering a callback from middle of registered list works
 */
HWTEST_F(NotificationHelperTest, NotificationHelper_unRegisterPhotoAlbumCallback_test_006, TestSize.Level1)
{
    MEDIA_INFO_LOG("NotificationHelper_unRegisterPhotoAlbumCallback_test_006 enter");

    auto callback1 = std::make_shared<MockPhotoAlbumChangeCallback>();
    auto callback2 = std::make_shared<MockPhotoAlbumChangeCallback>();
    auto callback3 = std::make_shared<MockPhotoAlbumChangeCallback>();

    NotificationHelper::RegisterPhotoAlbumCallback(callback1);
    NotificationHelper::RegisterPhotoAlbumCallback(callback2);
    NotificationHelper::RegisterPhotoAlbumCallback(callback3);

    // Unregister middle one
    int32_t ret = NotificationHelper::unRegisterPhotoAlbumCallback(callback2);
    EXPECT_EQ(ret, 0);

    // Verify others still registered
    ret = NotificationHelper::unRegisterPhotoAlbumCallback(callback1);
    EXPECT_EQ(ret, 0);
    ret = NotificationHelper::unRegisterPhotoAlbumCallback(callback3);
    EXPECT_EQ(ret, 0);

    MEDIA_INFO_LOG("NotificationHelper_unRegisterPhotoAlbumCallback_test_006 exit");
}

/**
 * @tc.number    : NotificationHelper_Callback_OnChange_test_009
 * @tc.name      : PhotoAlbumChangeCallback: OnChange with empty AlbumChangeDatas
 * @tc.desc      : Verify OnChange handles empty albumChangeDatas vector
 */
HWTEST_F(NotificationHelperTest, NotificationHelper_Callback_OnChange_test_009, TestSize.Level1)
{
    MEDIA_INFO_LOG("NotificationHelper_Callback_OnChange_test_009 enter");

    auto callback = std::make_shared<MockPhotoAlbumChangeCallback>();
    ASSERT_NE(callback, nullptr);

    AlbumChangeInfos testInfo;
    testInfo.type = NotifyChangeType::NOTIFY_CHANGE_UPDATE;
    testInfo.albumChangeDatas.clear(); // Empty vector

    int32_t ret = callback->OnChange(testInfo);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(callback->GetCallCount(), 1);
    EXPECT_EQ(callback->GetLastInfo().albumChangeDatas.size(), 0);

    MEDIA_INFO_LOG("NotificationHelper_Callback_OnChange_test_009 exit");
}

/**
 * @tc.number    : NotificationHelper_Callback_OnChange_test_010
 * @tc.name      : PhotoAlbumChangeCallback: OnChange with multiple AlbumChangeData
 * @tc.desc      : Verify OnChange handles multiple AlbumChangeData entries
 */
HWTEST_F(NotificationHelperTest, NotificationHelper_Callback_OnChange_test_010, TestSize.Level1)
{
    MEDIA_INFO_LOG("NotificationHelper_Callback_OnChange_test_010 enter");

    auto callback = std::make_shared<MockPhotoAlbumChangeCallback>();
    ASSERT_NE(callback, nullptr);

    AlbumChangeInfos testInfo;
    testInfo.type = NotifyChangeType::NOTIFY_CHANGE_UPDATE;

    const int32_t DATA_COUNT = 10;
    for (int32_t i = 0; i < DATA_COUNT; i++) {
        AlbumChangeData changeData;
        changeData.version = i;
        testInfo.albumChangeDatas.push_back(changeData);
    }

    callback->OnChange(testInfo);
    EXPECT_EQ(callback->GetLastInfo().albumChangeDatas.size(), DATA_COUNT);

    MEDIA_INFO_LOG("NotificationHelper_Callback_OnChange_test_010 exit");
}

/**
 * @tc.number    : NotificationHelper_Thread_Safety_test_004
 * @tc.name      : Thread safety: Rapid register/unregister cycles
 * @tc.desc      : Verify system handles rapid register/unregister cycles from multiple threads
 */
HWTEST_F(NotificationHelperTest, NotificationHelper_Thread_Safety_test_004, TestSize.Level1)
{
    MEDIA_INFO_LOG("NotificationHelper_Thread_Safety_test_004 enter");

    const int32_t threadCount = 5;
    const int32_t cyclesPerThread = 20;
    std::atomic<int32_t> successCount(0);

    // Lambda dışarı alındı → derinlik azaldı
    auto threadTask = [&successCount, cyclesPerThread]() {
        for (int32_t j = 0; j < cyclesPerThread; j++) {
            auto callback = std::make_shared<PhotoAlbumCallback>();
            int32_t ret = NotificationHelper::RegisterPhotoAlbumCallback(callback);
            if (ret != 0) continue;
            successCount++;
            NotificationHelper::unRegisterPhotoAlbumCallback(callback);
        }
    };

    std::vector<std::thread> threads;
    for (int32_t i = 0; i < threadCount; i++) {
        threads.emplace_back(threadTask);
    }

    for (auto& thread : threads) {
        thread.join();
    }

    EXPECT_EQ(successCount.load(), threadCount * cyclesPerThread);
    
    MEDIA_INFO_LOG("NotificationHelper_Thread_Safety_test_004 exit");
}

/**
 * @tc.number    : NotificationHelper_Edge_Case_test_013
 * @tc.name      : Edge case: Callback destruction during notification
 * @tc.desc      : Verify system handles callback destruction gracefully
 */
HWTEST_F(NotificationHelperTest, NotificationHelper_Edge_Case_test_013, TestSize.Level1)
{
    MEDIA_INFO_LOG("NotificationHelper_Edge_Case_test_013 enter");

    {
        auto callback = std::make_shared<MockPhotoAlbumChangeCallback>();
        NotificationHelper::RegisterPhotoAlbumCallback(callback);
        // Callback goes out of scope
    }

    // Register new callback should work
    auto newCallback = std::make_shared<MockPhotoAlbumChangeCallback>();
    int32_t ret = NotificationHelper::RegisterPhotoAlbumCallback(newCallback);
    EXPECT_EQ(ret, 0);

    NotificationHelper::unRegisterPhotoAlbumCallback(newCallback);

    MEDIA_INFO_LOG("NotificationHelper_Edge_Case_test_013 exit");
}

/**
 * @tc.number    : NotificationHelper_Edge_Case_test_014
 * @tc.name      : Edge case: Register/unregister with same pointer different instances
 * @tc.desc      : Verify system distinguishes between different callback instances
 */
HWTEST_F(NotificationHelperTest, NotificationHelper_Edge_Case_test_014, TestSize.Level1)
{
    MEDIA_INFO_LOG("NotificationHelper_Edge_Case_test_014 enter");

    auto callback1 = std::make_shared<MockPhotoAlbumChangeCallback>();
    auto callback2 = std::make_shared<MockPhotoAlbumChangeCallback>();

    // Verify they are different instances
    EXPECT_NE(callback1.get(), callback2.get());

    NotificationHelper::RegisterPhotoAlbumCallback(callback1);
    NotificationHelper::RegisterPhotoAlbumCallback(callback2);

    // Unregister one should not affect the other
    int32_t ret = NotificationHelper::unRegisterPhotoAlbumCallback(callback1);
    EXPECT_EQ(ret, 0);

    ret = NotificationHelper::unRegisterPhotoAlbumCallback(callback2);
    EXPECT_EQ(ret, 0);

    MEDIA_INFO_LOG("NotificationHelper_Edge_Case_test_014 exit");
}

/**
 * @tc.number    : NotificationHelper_PhotoAlbum_SetGet_Test_005
 * @tc.name      : PhotoAlbum SetSceneId boundary values test
 * @tc.desc      : Verify SetSceneId handles boundary values correctly
 */
HWTEST_F(NotificationHelperTest, NotificationHelper_PhotoAlbum_SetGet_Test_005, TestSize.Level1)
{
    MEDIA_INFO_LOG("NotificationHelper_PhotoAlbum_SetGet_Test_005 enter");

    PhotoAlbum photoAlbum;

    // Test boundary values
    const int32_t MIN_INT32 = INT32_MIN;
    const int32_t MAX_INT32 = INT32_MAX;
    const int32_t ZERO = 0;

    photoAlbum.SetSceneId(MIN_INT32);
    EXPECT_EQ(photoAlbum.GetSceneId(), MIN_INT32);

    photoAlbum.SetSceneId(MAX_INT32);
    EXPECT_EQ(photoAlbum.GetSceneId(), MAX_INT32);

    photoAlbum.SetSceneId(ZERO);
    EXPECT_EQ(photoAlbum.GetSceneId(), ZERO);

    MEDIA_INFO_LOG("NotificationHelper_PhotoAlbum_SetGet_Test_005 exit");
}

/**
 * @tc.number    : NotificationHelper_PhotoAlbum_SetGet_Test_006
 * @tc.name      : PhotoAlbum SetShareType boundary values test
 * @tc.desc      : Verify SetShareType handles boundary values correctly
 */
HWTEST_F(NotificationHelperTest, NotificationHelper_PhotoAlbum_SetGet_Test_006, TestSize.Level1)
{
    MEDIA_INFO_LOG("NotificationHelper_PhotoAlbum_SetGet_Test_006 enter");

    PhotoAlbum photoAlbum;

    // Test boundary values
    const int32_t MIN_INT32 = INT32_MIN;
    const int32_t MAX_INT32 = INT32_MAX;
    const int32_t ZERO = 0;

    photoAlbum.SetShareType(MIN_INT32);
    EXPECT_EQ(photoAlbum.GetShareType(), MIN_INT32);

    photoAlbum.SetShareType(MAX_INT32);
    EXPECT_EQ(photoAlbum.GetShareType(), MAX_INT32);

    photoAlbum.SetShareType(ZERO);
    EXPECT_EQ(photoAlbum.GetShareType(), ZERO);

    MEDIA_INFO_LOG("NotificationHelper_PhotoAlbum_SetGet_Test_006 exit");
}

/**
 * @tc.number    : NotificationHelper_PhotoAlbum_SetGet_Test_007
 * @tc.name      : PhotoAlbum SetSceneId and SetShareType sequence test
 * @tc.desc      : Verify SetSceneId and SetShareType work correctly in different sequences
 */
HWTEST_F(NotificationHelperTest, NotificationHelper_PhotoAlbum_SetGet_Test_007, TestSize.Level1)
{
    MEDIA_INFO_LOG("NotificationHelper_PhotoAlbum_SetGet_Test_007 enter");

    PhotoAlbum photoAlbum;

    // Sequence 1: SetSceneId first, then SetShareType
    photoAlbum.SetSceneId(100);
    photoAlbum.SetShareType(200);
    EXPECT_EQ(photoAlbum.GetSceneId(), 100);
    EXPECT_EQ(photoAlbum.GetShareType(), 200);

    // Sequence 2: SetShareType first, then SetSceneId
    photoAlbum.SetShareType(300);
    photoAlbum.SetSceneId(400);
    EXPECT_EQ(photoAlbum.GetSceneId(), 400);
    EXPECT_EQ(photoAlbum.GetShareType(), 300);

    // Sequence 3: Multiple sets
    photoAlbum.SetSceneId(500);
    photoAlbum.SetSceneId(600);
    photoAlbum.SetShareType(700);
    photoAlbum.SetShareType(800);
    EXPECT_EQ(photoAlbum.GetSceneId(), 600);
    EXPECT_EQ(photoAlbum.GetShareType(), 800);

    MEDIA_INFO_LOG("NotificationHelper_PhotoAlbum_SetGet_Test_007 exit");
}

/**
 * @tc.number    : NotificationHelper_PhotoAlbum_Database_Test_003
 * @tc.name      : PhotoAlbum database: Update only scene_id
 * @tc.desc      : Verify updating only scene_id without share_type works correctly
 */
HWTEST_F(NotificationHelperTest, NotificationHelper_PhotoAlbum_Database_Test_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("NotificationHelper_PhotoAlbum_Database_Test_003 enter");

    if (g_rdbStore == nullptr) {
        MEDIA_WARN_LOG("g_rdbStore is nullptr, skipping database test");
        return;
    }

    const string albumName = "NotificationHelper_PhotoAlbum_Database_Test_003";
    int32_t albumId = CreatePhotoAlbum(albumName);
    ASSERT_GT(albumId, 0);

    // Update only scene_id
    const int32_t TEST_SCENE_ID = 500;

    DataShareValuesBucket values;
    values.Put(PhotoAlbumColumns::ALBUM_SCENE_ID, TEST_SCENE_ID);

    DataSharePredicates predicates;
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, albumId);
    EXPECT_EQ(UpdatePhotoAlbum(values, predicates), 0);

    // Query and verify
    RdbPredicates queryPredicates(PhotoAlbumColumns::TABLE);
    queryPredicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, to_string(albumId));

    const vector<string> columns = {
        PhotoAlbumColumns::ALBUM_SCENE_ID,
        PhotoAlbumColumns::ALBUM_SHARE_TYPE,
    };

    auto resultSet = g_rdbStore->Query(queryPredicates, columns);
    ASSERT_NE(resultSet, nullptr);
    CHECK_AND_RETURN_LOG(resultSet->GoToFirstRow() == E_OK, "Failed to GoToFirstRow!");

    CheckColumn(resultSet, PhotoAlbumColumns::ALBUM_SCENE_ID, TYPE_INT32, TEST_SCENE_ID);
    // share_type should remain 0 (default)
    CheckColumn(resultSet, PhotoAlbumColumns::ALBUM_SHARE_TYPE, TYPE_INT32, 0);

    MEDIA_INFO_LOG("NotificationHelper_PhotoAlbum_Database_Test_003 exit");
}
} // namespace Media
} // namespace OHOS


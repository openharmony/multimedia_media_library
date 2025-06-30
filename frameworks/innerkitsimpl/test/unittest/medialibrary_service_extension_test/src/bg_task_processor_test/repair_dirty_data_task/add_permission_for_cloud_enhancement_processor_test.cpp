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

#include "values_bucket.h"
#include "rdb_utils.h"
#include "rdb_predicates.h"
#include "result_set_utils.h"
#include "media_log.h"
#include "medialibrary_db_const_sqls.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_type_const.h"
#include "media_file_utils.h"
#include "photo_file_utils.h"
#include "media_app_uri_permission_column.h"
#include "media_library_extend_manager.h"
#include "preferences.h"
#include "preferences_helper.h"

#define private public
#include "add_permission_for_cloud_enhancement_processor.h"
#undef private

using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {
static const std::string TASK_PROGRESS_EL2_DIR = "/data/storage/el2";
static const std::string TASK_PROGRESS_BASE_DIR = "/data/storage/el2/base";
static const std::string TASK_PROGRESS_PREFERENCES_DIR = "/data/storage/el2/base/preferences";
static const std::string TASK_PROGRESS_XML = "/data/storage/el2/base/preferences/task_progress.xml";

static const std::string PERMISSION_ADDED_FILE_ID = "permission_added_file_id";

static const int32_t PERMISSION_ADDED_FILE_ID_fu1 = -1;
static const int32_t PERMISSION_ADDED_FILE_ID_0 = 0;
static const int32_t PERMISSION_ADDED_FILE_ID_1 = 1;
static const int32_t PERMISSION_ADDED_FILE_ID_2 = 2;
static const int32_t PERMISSION_ADDED_FILE_ID_10 = 10;

bool CreateTaskProgressXml()
{
    if (!MediaFileUtils::IsDirectory(TASK_PROGRESS_EL2_DIR)) {
        MediaFileUtils::CreateDirectory(TASK_PROGRESS_EL2_DIR);
    }

    if (!MediaFileUtils::IsDirectory(TASK_PROGRESS_BASE_DIR)) {
        MediaFileUtils::CreateDirectory(TASK_PROGRESS_BASE_DIR);
    }

    if (!MediaFileUtils::IsDirectory(TASK_PROGRESS_PREFERENCES_DIR)) {
        MediaFileUtils::CreateDirectory(TASK_PROGRESS_PREFERENCES_DIR);
    }

    if (!MediaFileUtils::IsFileExists(TASK_PROGRESS_XML)) {
        MediaFileUtils::CreateFile(TASK_PROGRESS_XML);
    }
    int32_t errCode = E_OK;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(TASK_PROGRESS_XML, errCode);
    if (prefs == nullptr) {
        MEDIA_ERR_LOG("get preferences error: %{public}d", errCode);
        return false;
    }
    return true;
}

int32_t InsertNormalAndStrongAsset(int64_t &normalFileId, int64_t &strongFileId)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return E_ERR;
    }

    // 插入normal数据
    NativeRdb::ValuesBucket normalValue;
    normalValue.Put(PhotoColumn::PHOTO_STRONG_ASSOCIATION,
        static_cast<int32_t>(StrongAssociationType::NORMAL));
    int32_t ret = rdbStore->Insert(normalFileId, PhotoColumn::PHOTOS_TABLE, normalValue);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("InsertAsset normal normalFileId: %{public}s", std::to_string(normalFileId).c_str());

    // 插入云增强数据
    NativeRdb::ValuesBucket strongValue;
    strongValue.Put(PhotoColumn::PHOTO_STRONG_ASSOCIATION,
        static_cast<int32_t>(StrongAssociationType::CLOUD_ENHANCEMENT));
    strongValue.Put(PhotoColumn::PHOTO_ASSOCIATE_FILE_ID, normalFileId);
    ret = rdbStore->Insert(strongFileId, PhotoColumn::PHOTOS_TABLE, strongValue);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("InsertAsset enhancement strong strongFileId: %{public}s", std::to_string(strongFileId).c_str());

    // 更新normal数据对应的关联id
    NativeRdb::RdbPredicates predicate(PhotoColumn::PHOTOS_TABLE);
    predicate.EqualTo(MediaColumn::MEDIA_ID, to_string(normalFileId));
    NativeRdb::ValuesBucket updateValues;
    updateValues.PutInt(PhotoColumn::PHOTO_ASSOCIATE_FILE_ID, strongFileId);

    int32_t rows = -1;
    ret = rdbStore->Update(rows, updateValues, predicate);
    CHECK_AND_RETURN_RET_LOG((ret == E_OK && rows > 0), E_ERR,
        "Failed to Update Enhancement Asset, ret: %{public}d, updateRows: %{public}d",
        ret, rows);

    return ret;
}

int32_t QueryPhotoCount(int32_t &count)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("can not get rdbstore");
        return E_ERR;
    }

    vector<string> columns = { MediaColumn::MEDIA_ID };
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::QUERY, MediaLibraryApi::API_10);
    auto resultSet = rdbStore->Query(cmd, columns);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("resultSet is nullptr");
        return E_ERR;
    }

    if (resultSet->GetRowCount(count) != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("failed to GetRowCount");
        return E_ERR;
    }
    resultSet->Close();
    return E_OK;
}

int32_t InsertPermissionAsset(int64_t fileId, int32_t permissionType)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();

    NativeRdb::ValuesBucket value;
    value.Put(AppUriPermissionColumn::FILE_ID, fileId);
    value.Put(AppUriPermissionColumn::PERMISSION_TYPE, permissionType);
    value.Put(AppUriPermissionColumn::URI_TYPE, 1);
    int64_t dateModified = 1749539819360;
    value.Put(AppUriPermissionColumn::DATE_MODIFIED, dateModified);
    int64_t tokenId = 537490057;
    value.Put(AppUriPermissionColumn::SOURCE_TOKENID, tokenId);
    value.Put(AppUriPermissionColumn::TARGET_TOKENID, tokenId);

    int64_t outRowId = -1;
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return E_ERR;
    }
    int32_t ret = rdbStore->Insert(outRowId,
        AppUriPermissionColumn::APP_URI_PERMISSION_TABLE, value);
    MEDIA_INFO_LOG("InsertPermissionAsset fileId: %{public}s, permissionType: %{public}d",
        std::to_string(fileId).c_str(), permissionType);
    return ret;
}

int32_t QueryPermission(int32_t fileId, int32_t &permissionType)
{
    if (fileId < 0) {
        MEDIA_ERR_LOG("this file id %{private}d is invalid", fileId);
        return E_ERR;
    }
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return E_ERR;
    }

    NativeRdb::RdbPredicates queryPredicates(AppUriPermissionColumn::APP_URI_PERMISSION_TABLE);
    queryPredicates.EqualTo(AppUriPermissionColumn::FILE_ID, fileId);
    vector<string> columns = { AppUriPermissionColumn::PERMISSION_TYPE };
    auto resultSet = MediaLibraryRdbStore::StepQueryWithoutCheck(queryPredicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr && resultSet->GoToFirstRow() == NativeRdb::E_OK,
        E_ERR, "cannot get permission from origin photo: %{public}d", fileId);
    permissionType = GetInt32Val(AppUriPermissionColumn::PERMISSION_TYPE, resultSet);
    resultSet->Close();
    MEDIA_INFO_LOG("fileId: %{public}d, permissionType: %{public}d", fileId, permissionType);
    return E_OK;
}

/**
 * @tc.name: AddPermissionForCloudEnhancement_test_001
 * @tc.desc: xml文件中没有permission_added_file_id字段, 则会初始化 permission_added_file_id = 0
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, AddPermissionForCloudEnhancement_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("AddPermissionForCloudEnhancement_test_001 start");
    // 初始化xml文件
    bool ret = CreateTaskProgressXml();
    EXPECT_EQ(ret, true);
    int32_t errCode = E_OK;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(TASK_PROGRESS_XML, errCode);
    EXPECT_NE(prefs, nullptr);
    EXPECT_EQ(errCode, E_OK);
    int32_t curFileId = prefs->GetInt(PERMISSION_ADDED_FILE_ID, 0);
    EXPECT_EQ(curFileId, PERMISSION_ADDED_FILE_ID_0);

    auto processor = AddPermissionForCloudEnhancementProcessor();
    processor.AddPermissionForCloudEnhancement();

    curFileId = prefs->GetInt(PERMISSION_ADDED_FILE_ID, 0);
    EXPECT_EQ(curFileId, PERMISSION_ADDED_FILE_ID_0);
    MEDIA_INFO_LOG("AddPermissionForCloudEnhancement_test_001 end");
}

/**
 * @tc.name: AddPermissionForCloudEnhancement_test_002
 * @tc.desc: 如果数据库中没有任何数据, 则会初始化 permission_added_file_id = 0
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, AddPermissionForCloudEnhancement_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("AddPermissionForCloudEnhancement_test_002 start");
    // 初始化xml文件
    bool ret = CreateTaskProgressXml();
    EXPECT_EQ(ret, true);
    int32_t errCode = E_OK;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(TASK_PROGRESS_XML, errCode);
    EXPECT_NE(prefs, nullptr);
    EXPECT_EQ(errCode, E_OK);
    prefs->PutInt(PERMISSION_ADDED_FILE_ID, PERMISSION_ADDED_FILE_ID_fu1);
    prefs->FlushSync();

    int32_t curFileId = prefs->GetInt(PERMISSION_ADDED_FILE_ID, 0);
    EXPECT_EQ(curFileId, PERMISSION_ADDED_FILE_ID_fu1);

    auto processor = AddPermissionForCloudEnhancementProcessor();
    processor.AddPermissionForCloudEnhancement();

    curFileId = prefs->GetInt(PERMISSION_ADDED_FILE_ID, 0);
    EXPECT_EQ(curFileId, PERMISSION_ADDED_FILE_ID_0);
    MEDIA_INFO_LOG("AddPermissionForCloudEnhancement_test_002 end");
}

/**
 * @tc.name: AddPermissionForCloudEnhancement_test_003
 * @tc.desc: 若 permission_added_file_id 的值超过了当前数据库中存在的资产数,
 *           不会更新任何数据, 并将修复 permission_added_file_id 为当前 max(file_id)
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, AddPermissionForCloudEnhancement_test_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("AddPermissionForCloudEnhancement_test_003 start");
    // 初始化xml文件
    bool createRet = CreateTaskProgressXml();
    EXPECT_EQ(createRet, true);
    int32_t errCode = E_OK;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(TASK_PROGRESS_XML, errCode);
    EXPECT_NE(prefs, nullptr);
    EXPECT_EQ(errCode, E_OK);
    prefs->PutInt(PERMISSION_ADDED_FILE_ID, PERMISSION_ADDED_FILE_ID_10);
    prefs->FlushSync();

    int32_t curFileId = prefs->GetInt(PERMISSION_ADDED_FILE_ID, 0);
    EXPECT_EQ(curFileId, PERMISSION_ADDED_FILE_ID_10);

    // 插入2条数据
    int64_t normalFileId = -1;
    int64_t strongFileId = -1;
    auto ret = InsertNormalAndStrongAsset(normalFileId, strongFileId);
    EXPECT_EQ(ret, E_OK);

    int32_t count = -1;
    ret = QueryPhotoCount(count);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count < PERMISSION_ADDED_FILE_ID_10, true);

    // 为 normal 数据插入权限
    ret = InsertPermissionAsset(normalFileId, static_cast<int32_t>(PhotoPermissionType::PERSIST_READWRITE_IMAGEVIDEO));
    EXPECT_EQ(ret, E_OK);

    auto processor = AddPermissionForCloudEnhancementProcessor();
    processor.AddPermissionForCloudEnhancement();
    curFileId = prefs->GetInt(PERMISSION_ADDED_FILE_ID, 0);
    EXPECT_EQ(curFileId, count);

    // 由于 permission_added_file_id 大于当前数据库存在的资产数目, 所以不会更新云增强数据
    int32_t permissionType = -1;
    ret = QueryPermission(strongFileId, permissionType);
    EXPECT_EQ(ret, E_ERR);
    MEDIA_INFO_LOG("AddPermissionForCloudEnhancement_test_003 end");
}

/**
 * @tc.name: AddPermissionForCloudEnhancement_test_004
 * @tc.desc: 若 permission_added_file_id 的值小于数据库中存在的资产数, 会更新权限数据
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, AddPermissionForCloudEnhancement_test_004, TestSize.Level1)
{
    MEDIA_INFO_LOG("AddPermissionForCloudEnhancement_test_004 start");
    // 初始化xml文件
    bool createRet = CreateTaskProgressXml();
    EXPECT_EQ(createRet, true);
    int32_t errCode = E_OK;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(TASK_PROGRESS_XML, errCode);
    EXPECT_NE(prefs, nullptr);
    EXPECT_EQ(errCode, E_OK);
    prefs->PutInt(PERMISSION_ADDED_FILE_ID, PERMISSION_ADDED_FILE_ID_1);
    prefs->FlushSync();

    int32_t curFileId = prefs->GetInt(PERMISSION_ADDED_FILE_ID, 0);
    EXPECT_EQ(curFileId, PERMISSION_ADDED_FILE_ID_1);

    // 插入2条数据
    int64_t normalFileId = -1;
    int64_t strongFileId = -1;
    auto ret = InsertNormalAndStrongAsset(normalFileId, strongFileId);
    EXPECT_EQ(ret, E_OK);

    int32_t count = -1;
    ret = QueryPhotoCount(count);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count > PERMISSION_ADDED_FILE_ID_1, true);

    // 为 normal 数据插入权限
    ret = InsertPermissionAsset(normalFileId, static_cast<int32_t>(PhotoPermissionType::PERSIST_READWRITE_IMAGEVIDEO));
    EXPECT_EQ(ret, E_OK);

    auto processor = AddPermissionForCloudEnhancementProcessor();
    processor.AddPermissionForCloudEnhancement();
    curFileId = prefs->GetInt(PERMISSION_ADDED_FILE_ID, 0);
    EXPECT_EQ(curFileId, count);

    // 由于 permission_added_file_id 大于当前数据库存在的资产数目, 所以不会更新云增强数据
    int32_t permissionType = -1;
    ret = QueryPermission(strongFileId, permissionType);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(permissionType, static_cast<int32_t>(PhotoPermissionType::PERSIST_READWRITE_IMAGEVIDEO));
    MEDIA_INFO_LOG("AddPermissionForCloudEnhancement_test_004 end");
}

/**
 * @tc.name: AddPermissionForCloudEnhancement_test_005
 * @tc.desc: 停止后台任务时, 会在 AddPermissionForCloudEnhancement 中打断
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, AddPermissionForCloudEnhancement_test_005, TestSize.Level1)
{
    MEDIA_INFO_LOG("AddPermissionForCloudEnhancement_test_005 start");
    // 初始化xml文件
    bool createRet = CreateTaskProgressXml();
    EXPECT_EQ(createRet, true);
    int32_t errCode = E_OK;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(TASK_PROGRESS_XML, errCode);
    EXPECT_NE(prefs, nullptr);
    EXPECT_EQ(errCode, E_OK);
    prefs->PutInt(PERMISSION_ADDED_FILE_ID, PERMISSION_ADDED_FILE_ID_1);
    prefs->FlushSync();

    int32_t curFileId = prefs->GetInt(PERMISSION_ADDED_FILE_ID, 0);
    EXPECT_EQ(curFileId, PERMISSION_ADDED_FILE_ID_1);

    // 插入4条数据, 因为不会在第一次停止。
    int64_t normalFileId = -1;
    int64_t strongFileId = -1;
    auto ret = InsertNormalAndStrongAsset(normalFileId, strongFileId);
    EXPECT_EQ(ret, E_OK);

    int64_t normalFileIdAgain = -1;
    int64_t strongFileIdAgain = -1;
    ret = InsertNormalAndStrongAsset(normalFileIdAgain, strongFileIdAgain);
    EXPECT_EQ(ret, E_OK);

    int32_t count = -1;
    ret = QueryPhotoCount(count);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count > PERMISSION_ADDED_FILE_ID_1, true);

    // 为 normal 数据插入权限
    ret = InsertPermissionAsset(normalFileId, static_cast<int32_t>(PhotoPermissionType::PERSIST_READWRITE_IMAGEVIDEO));
    EXPECT_EQ(ret, E_OK);
    // 为 normalAgain 数据插入权限
    ret = InsertPermissionAsset(normalFileIdAgain,
        static_cast<int32_t>(PhotoPermissionType::PERSIST_READWRITE_IMAGEVIDEO));
    EXPECT_EQ(ret, E_OK);

    auto processor = AddPermissionForCloudEnhancementProcessor();
    ret = processor.Stop("");
    EXPECT_EQ(ret, E_OK);
    processor.AddPermissionForCloudEnhancement();
    curFileId = prefs->GetInt(PERMISSION_ADDED_FILE_ID, 0);
    EXPECT_EQ(curFileId, PERMISSION_ADDED_FILE_ID_2);

    // 由于 AddPermissionForCloudEnhancement, 权限数据不会更新, permission_added_file_id 维持原有数据
    int32_t permissionType = -1;
    ret = QueryPermission(strongFileIdAgain, permissionType);
    EXPECT_EQ(ret, E_ERR);
    MEDIA_INFO_LOG("AddPermissionForCloudEnhancement_test_005 end");
}
} // namespace Media
} // namespace OHOS

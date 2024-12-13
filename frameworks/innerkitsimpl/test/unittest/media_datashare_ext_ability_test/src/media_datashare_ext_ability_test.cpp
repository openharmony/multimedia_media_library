/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#define MLOG_TAG "MediaDatashareExtAbilityUnitTest"

#include "media_datashare_ext_ability_test.h"

#include <chrono>
#include <thread>

#include "ability_context_impl.h"
#include "data_ability_observer_interface.h"
#include "datashare_business_error.h"
#include "datashare_helper.h"
#include "datashare_predicates.h"
#include "datashare_values_bucket.h"
#include "get_self_permissions.h"
#include "media_datashare_ext_ability.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_db_const.h"
#include "medialibrary_db_const_sqls.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "media_column.h"
#include "media_file_ext_ability.h"
#include "media_datashare_stub_impl.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "runtime.h"
#include "userfilemgr_uri.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::AbilityRuntime;
using namespace OHOS::DataShare;
namespace OHOS {
namespace Media {
static shared_ptr<MediaLibraryRdbStore> g_rdbStore;
static const int32_t SLEEP_FOR_SECONDS = 5;

class ArkJsRuntime : public AbilityRuntime::JsRuntime {
public:
    ArkJsRuntime() {};

    ~ArkJsRuntime() {};

    void StartDebugMode(const DebugOption debugOption) {};
    void FinishPreload() {};
    bool LoadRepairPatch(const string& patchFile, const string& baseFile)
    {
        return true;
    };
    bool NotifyHotReloadPage()
    {
        return true;
    };
    bool UnLoadRepairPatch(const string& patchFile)
    {
        return true;
    };
    bool RunScript(const string& path, const string& hapPath, bool useCommonChunk = false)
    {
        return true;
    };
};

void CleanTestTables()
{
    vector<string> dropTableList = {
        PhotoColumn::PHOTOS_TABLE,
        MEDIALIBRARY_TABLE
    };
    for (auto &dropTable : dropTableList) {
        string dropSql = "DROP TABLE " + dropTable + ";";
        int32_t ret = g_rdbStore->ExecuteSql(dropSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Drop %{public}s table failed", dropTable.c_str());
            return;
        }
        MEDIA_DEBUG_LOG("Drop %{public}s table success", dropTable.c_str());
    }
}

void SetTables()
{
    vector<string> createTableSqlList = {
        PhotoColumn::CREATE_PHOTO_TABLE,
        CREATE_MEDIA_TABLE,
    };
    for (auto &createTableSql : createTableSqlList) {
        int32_t ret = g_rdbStore->ExecuteSql(createTableSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Execute sql %{private}s failed", createTableSql.c_str());
            return;
        }
        MEDIA_DEBUG_LOG("Execute sql %{private}s success", createTableSql.c_str());
    }
}

void ClearAndRestart()
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MediaLibraryUnitTestUtils::Init();
    }

    system("rm -rf /storage/cloud/files/*");
    system("rm -rf /storage/cloud/files/.thumbs");
    system("rm -rf /storage/cloud/files/.editData");
    for (const auto &dir : TEST_ROOT_DIRS) {
        string ROOT_PATH = "/storage/cloud/100/files/";
        bool ret = MediaFileUtils::CreateDirectory(ROOT_PATH + dir + "/");
        CHECK_AND_PRINT_LOG(ret, "make %{public}s dir failed, ret=%{public}d", dir.c_str(), ret);
    }
    CleanTestTables();
    SetTables();
}

static inline MediaDataShareExtAbility Init()
{
    const std::unique_ptr<AbilityRuntime::Runtime> runtime;
    return {(*runtime)};
}

void MediaDatashareExtAbilityTest::SetUpTestCase(void)
{
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start MediaLibraryPhotoOperationsTest failed, can not get rdbstore");
        exit(1);
    }
    SetTables();
    MEDIA_INFO_LOG("MediaLibraryManagerTest::SetUpTestCase:: Finish");
}

void MediaDatashareExtAbilityTest::TearDownTestCase(void)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MediaLibraryUnitTestUtils::Init();
    }

    system("rm -rf /storage/cloud/files/*");
    ClearAndRestart();
    g_rdbStore = nullptr;
    MediaLibraryDataManager::GetInstance()->ClearMediaLibraryMgr();
    this_thread::sleep_for(chrono::seconds(SLEEP_FOR_SECONDS));
    MEDIA_INFO_LOG("Clean is finish");
    MEDIA_ERR_LOG("TearDownTestCase finish");
}

// SetUp:Execute before each test case
void MediaDatashareExtAbilityTest::SetUp()
{
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start MediaLibraryCloudAssetDownloadTest failed, can not get rdbstore");
        exit(1);
    }
    ClearAndRestart();
}

void MediaDatashareExtAbilityTest::TearDown(void) {}

struct PhotoResult {
    int64_t fileId;
    int32_t mediaType;
    string path;
    string displayName;
};

string ReturnUri(string uriType, string mainUri, string subUri = "")
{
    if (subUri.empty()) {
        return (uriType + "/" + mainUri);
    } else {
        return (uriType + "/" + mainUri + "/" + subUri);
    }
}

void InsertAsset(PhotoResult &result)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    EXPECT_NE(rdbStore, nullptr);

    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutInt(MediaColumn::MEDIA_TYPE, result.mediaType);
    valuesBucket.PutString(MediaColumn::MEDIA_NAME, result.displayName);
    valuesBucket.PutString(MediaColumn::MEDIA_FILE_PATH, result.path);

    int32_t ret = rdbStore->Insert(result.fileId, PhotoColumn::PHOTOS_TABLE, valuesBucket);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaDatashareExtAbilityTest, Extension_Insert_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Extension_Insert_001::Start");
    auto extension = Init();
    extension.InitPermissionHandler();

    Uri insertUri(URI_CREATE_FILE);
    DataShare::DataShareValuesBucket valuesBucket;
    string relativePath = "Pictures/";
    string displayName = "CreateAsset_Test_001.jpg";
    MediaType mediaType = MEDIA_TYPE_IMAGE;
    valuesBucket.Put(MediaColumn::MEDIA_TYPE, mediaType);
    valuesBucket.Put(MediaColumn::MEDIA_NAME, displayName);
    valuesBucket.Put(MediaColumn::MEDIA_FILE_PATH, relativePath);
    auto retVal = extension.Insert(insertUri, valuesBucket);
    EXPECT_EQ((retVal > 0), true);
}

HWTEST_F(MediaDatashareExtAbilityTest, Extension_Update_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Extension_Update_001::Start");
    auto extension = Init();
    extension.InitPermissionHandler();

    Uri updateUri(CMAM_CLOUD_MEDIA_ASSET_TASK_START_FORCE);
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    auto ret = extension.Update(updateUri, predicates, valuesBucket);
    EXPECT_EQ((ret > 0), false);
}

HWTEST_F(MediaDatashareExtAbilityTest, Extension_Update_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Extension_Update_002::Start");
    auto extension = Init();
    extension.InitPermissionHandler();

    struct PhotoResult photoAsset = {-1, static_cast<int32_t>(MEDIA_TYPE_IMAGE), "UpdateTest_002.jpg", "Pictures/"};
    InsertAsset(photoAsset);

    Uri updateUri(PAH_UPDATE_PHOTO);
    string updateDisplayName = "Modify_001.jpg";
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MediaColumn::MEDIA_NAME, updateDisplayName);

    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(MediaColumn::MEDIA_ID, photoAsset.fileId);
    auto ret = extension.Update(updateUri, predicates, valuesBucket);
    EXPECT_EQ(ret, 1);
}

HWTEST_F(MediaDatashareExtAbilityTest, Extension_Delete_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Extension_Delete_001::Start");
    auto extension = Init();
    extension.InitPermissionHandler();

    struct PhotoResult photoAsset = {-1, static_cast<int32_t>(MEDIA_TYPE_IMAGE), "DeleteTest_001.jpg", "Pictures/"};
    InsertAsset(photoAsset);

    Uri deleteUri(PAH_TRASH_PHOTO);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(MediaColumn::MEDIA_ID, photoAsset.fileId);
    auto ret = extension.Delete(deleteUri, predicates);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(MediaDatashareExtAbilityTest, Extension_Query_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Extension_Query_001::Start");
    auto extension = Init();
    extension.InitPermissionHandler();

    struct PhotoResult photoAsset = {-1, static_cast<int32_t>(MEDIA_TYPE_IMAGE), "QueryTest_001.jpg", "Pictures/"};
    InsertAsset(photoAsset);

    Uri queryUri(PAH_QUERY_PHOTO);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(MediaColumn::MEDIA_ID, photoAsset.fileId);

    vector<string> columns = {MediaColumn::MEDIA_ID, MediaColumn::MEDIA_NAME};
    DataShare::DatashareBusinessError businessError;
    auto result = extension.Query(queryUri, predicates, columns, businessError);
    EXPECT_NE(result, nullptr);
}

HWTEST_F(MediaDatashareExtAbilityTest, Extension_GetType_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Extension_GetType_001::Start");
    auto extension = Init();
    extension.InitPermissionHandler();

    Uri getTypeUri(CMAM_CLOUD_MEDIA_ASSET_TASK_STATUS_QUERY);
    string result = extension.GetType(getTypeUri);
    EXPECT_EQ(result, "2,0,0,0,0,0");
}

HWTEST_F(MediaDatashareExtAbilityTest, Extension_RegisterObserver_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Extension_RegisterObserver_001::Start");
    auto extension = Init();
    extension.InitPermissionHandler();

    Uri registerObserverUri(MEDIALIBRARY_IMAGE_URI);
    sptr<AAFwk::IDataAbilityObserver> dataObserver;
    bool ret = extension.RegisterObserver(registerObserverUri, dataObserver);
    EXPECT_NE(dataObserver, nullptr);
    EXPECT_EQ(ret, true);

    ret = extension.UnregisterObserver(registerObserverUri, dataObserver);
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaDatashareExtAbilityTest, Extension_NotifyChange_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Extension_NotifyChange_001::Start");
    auto extension = Init();
    extension.InitPermissionHandler();

    Uri notifyChangeUri(MEDIALIBRARY_IMAGE_URI);
    bool ret = extension.NotifyChange(notifyChangeUri);
    EXPECT_EQ(ret, true);
}
} // namespace Media
} // namespace OHOS
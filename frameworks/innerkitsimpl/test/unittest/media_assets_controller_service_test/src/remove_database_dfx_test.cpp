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

#define MLOG_TAG "MediaAssetsControllerServiceTest"

#include "remove_database_dfx_test.h"

#include <string>
#include <vector>

#define private public
#define protected public
#include "media_assets_controller_service.h"
#undef private
#undef protected

#include "medialibrary_data_manager.h"
#include "remove_database_dfx_vo.h"
#include "get_database_dfx_vo.h"
#include "media_assets_service.h"
#include "user_define_ipc_client.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_unistore_manager.h"

namespace OHOS::Media {
using namespace std;
using namespace testing::ext;
using namespace OHOS::NativeRdb;


static shared_ptr<MediaLibraryRdbStore> g_rdbStore;
static shared_ptr<MediaAssetsControllerService> controllerService;
static constexpr int32_t SLEEP_SECONDS = 1;

static int32_t ClearTable(const string &table)
{
    RdbPredicates predicates(table);

    int32_t rows = 0;
    int32_t err = g_rdbStore->Delete(rows, predicates);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to clear photos table, err: %{public}d", err);
        return E_HAS_DB_ERROR;
    }
    return E_OK;
}

void RemoveDatabaseDFXTest::SetUpTestCase(void)
{
    MediaLibraryUnitTestUtils::Init();
    controllerService = make_shared<MediaAssetsControllerService>();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start MediaLibraryPhotoOperationsTest failed, can not get g_rdbStore");
        exit(1);
    }
    ClearTable(PhotoColumn::PHOTOS_TABLE);
    MEDIA_INFO_LOG("SetUpTestCase");
}

void RemoveDatabaseDFXTest::TearDownTestCase(void)
{
    ClearTable(PhotoColumn::PHOTOS_TABLE);
    MEDIA_INFO_LOG("TearDownTestCase");
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_SECONDS));
}

void RemoveDatabaseDFXTest::SetUp()
{
    ClearTable(PhotoColumn::PHOTOS_TABLE);
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_SECONDS));
    MEDIA_INFO_LOG("SetUp");
}

void RemoveDatabaseDFXTest::TearDown(void)
{
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_SECONDS));
    MEDIA_INFO_LOG("TearDown");
}

HWTEST_F(RemoveDatabaseDFXTest, RemoveDatabaseDFX_Test_001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;

    int32_t ret = controllerService->RemoveDatabaseDFX(data, reply);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(RemoveDatabaseDFXTest, RemoveDatabaseDFX_Test_002, TestSize.Level0)
{
    // 测试失败分支
    MessageParcel data;
    MessageParcel reply;
    RemoveDatabaseDFXReqBody reqBody;
    std::string betaId = "123456789";
    reqBody.betaId = betaId;
    bool isValid = reqBody.Marshalling(data);
    int32_t ret = controllerService->RemoveDatabaseDFX(data, reply);
    EXPECT_EQ(ret, E_FILE_OPER_FAIL);
    // 构建测试成功条件
    MessageParcel data0;
    MessageParcel reply0;
    GetDatabaseDFXReqBody reqBody0;
    reqBody0.betaId = betaId;
    isValid = reqBody0.Marshalling(data0);
    ret = controllerService->GetDatabaseDFX(data0, reply0);
    // 测试成功分支
    MessageParcel data1;
    MessageParcel reply1;
    isValid = reqBody.Marshalling(data1);
    EXPECT_EQ(isValid, true);
    ret = controllerService->RemoveDatabaseDFX(data1, reply1);
    EXPECT_EQ(ret, E_OK);
}
}  // namespace OHOS::Media
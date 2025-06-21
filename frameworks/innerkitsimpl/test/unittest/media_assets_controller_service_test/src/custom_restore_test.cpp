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

#include "custom_restore_test.h"

#include <string>
#include <vector>

#define private public
#define protected public
#include "media_assets_controller_service.h"
#undef private
#undef protected

#include "restore_vo.h"
#include "stop_restore_vo.h"

#include "user_define_ipc_client.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_unistore_manager.h"
#include "media_file_uri.h"

namespace OHOS::Media {
using namespace std;
using namespace testing::ext;
using namespace OHOS::NativeRdb;
using OHOS::DataShare::DataSharePredicates;

static shared_ptr<MediaLibraryRdbStore> g_rdbStore;
static constexpr int32_t SLEEP_ONE_SECOND = 1;

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

void CustomRestoreTest::SetUpTestCase(void)
{
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start MediaLibraryPhotoOperationsTest failed, can not get g_rdbStore");
        exit(1);
    }
    ClearTable(PhotoColumn::PHOTOS_TABLE);
    MEDIA_INFO_LOG("SetUpTestCase");
}

void CustomRestoreTest::TearDownTestCase(void)
{
    ClearTable(PhotoColumn::PHOTOS_TABLE);
    MEDIA_INFO_LOG("TearDownTestCase");
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_ONE_SECOND));
}

void CustomRestoreTest::SetUp()
{
    ClearTable(PhotoColumn::PHOTOS_TABLE);
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_ONE_SECOND));
    MEDIA_INFO_LOG("SetUp");
}

void CustomRestoreTest::TearDown(void)
{
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_ONE_SECOND * 2));
    MEDIA_INFO_LOG("TearDown");
}

HWTEST_F(CustomRestoreTest, CustomRestoreTest_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("CustomRestoreTest_Test_001 for Restore Begin");
    RestoreReqBody reqBody;
    reqBody.albumLpath = "/RestoreTest_Test_albumLpath";
    reqBody.keyPath = "RestoreTest_Test_keyPath";
    reqBody.bundleName = "RestoreTest_Test_bundleName";
    reqBody.appName = "RestoreTest_Test_appName";
    reqBody.appId = "RestoreTest_Test_appId";
    reqBody.isDeduplication = true;

    MessageParcel data;
    ASSERT_EQ(reqBody.Marshalling(data), true);

    MessageParcel reply;
    auto service = make_shared<MediaAssetsControllerService>();
    service->Restore(data, reply);

    IPC::MediaRespVo<IPC::MediaEmptyObjVo> respVo;
    ASSERT_EQ(respVo.Unmarshalling(reply), true);

    MEDIA_INFO_LOG("Restore ErrCode:%{public}d", respVo.GetErrCode());
    ASSERT_EQ(respVo.GetErrCode(), E_NO_SUCH_FILE);
}

HWTEST_F(CustomRestoreTest, CustomRestoreTest_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("CustomRestoreTest_Test_002 for Restore Begin");
    RestoreReqBody reqBody;
    MessageParcel data;
    ASSERT_EQ(reqBody.Marshalling(data), true);

    MessageParcel reply;
    auto service = make_shared<MediaAssetsControllerService>();
    service->Restore(data, reply);

    IPC::MediaRespVo<IPC::MediaEmptyObjVo> respVo;
    ASSERT_EQ(respVo.Unmarshalling(reply), true);

    MEDIA_INFO_LOG("Restore respVo ErrCode:%{public}d", respVo.GetErrCode());
    ASSERT_LT(respVo.GetErrCode(), 0);

    MessageParcel data1;
    MessageParcel reply1;
    service->Restore(data1, reply1);

    IPC::MediaRespVo<IPC::MediaEmptyObjVo> respVo1;
    ASSERT_EQ(respVo1.Unmarshalling(reply1), true);

    MEDIA_INFO_LOG("Restore respVo1 ErrCode:%{public}d", respVo1.GetErrCode());
    ASSERT_LT(respVo1.GetErrCode(), 0);
}

HWTEST_F(CustomRestoreTest, CustomRestoreTest_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("CustomRestoreTest_Test_003 for StopRestore Begin");
    StopRestoreReqBody reqBody;
    reqBody.keyPath = "StopRestoreTest_Test_keyPath";

    MessageParcel data;
    ASSERT_EQ(reqBody.Marshalling(data), true);

    MessageParcel reply;
    auto service = make_shared<MediaAssetsControllerService>();
    service->StopRestore(data, reply);

    IPC::MediaRespVo<IPC::MediaEmptyObjVo> respVo;
    ASSERT_EQ(respVo.Unmarshalling(reply), true);

    MEDIA_INFO_LOG("StopRestore ErrCode:%{public}d", respVo.GetErrCode());
    ASSERT_EQ(respVo.GetErrCode(), 0);
}

HWTEST_F(CustomRestoreTest, CustomRestoreTest_Test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("CustomRestoreTest_Test_004 for StopRestore Begin");
    StopRestoreReqBody reqBody;
    MessageParcel data;
    ASSERT_EQ(reqBody.Marshalling(data), true);

    MessageParcel reply;
    auto service = make_shared<MediaAssetsControllerService>();
    service->StopRestore(data, reply);

    IPC::MediaRespVo<IPC::MediaEmptyObjVo> respVo;
    ASSERT_EQ(respVo.Unmarshalling(reply), true);

    MEDIA_INFO_LOG("StopRestore respVo ErrCode:%{public}d", respVo.GetErrCode());
    ASSERT_LT(respVo.GetErrCode(), 0);

    MessageParcel data1;
    MessageParcel reply1;
    service->StopRestore(data1, reply1);

    IPC::MediaRespVo<IPC::MediaEmptyObjVo> respVo1;
    ASSERT_EQ(respVo1.Unmarshalling(reply1), true);

    MEDIA_INFO_LOG("StopRestore respVo1 ErrCode:%{public}d", respVo1.GetErrCode());
    ASSERT_LT(respVo1.GetErrCode(), 0);
}
}  // namespace OHOS::Media
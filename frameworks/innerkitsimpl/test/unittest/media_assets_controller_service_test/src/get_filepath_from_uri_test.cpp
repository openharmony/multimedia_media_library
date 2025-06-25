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

#include "get_filepath_from_uri_test.h"

#include <string>
#include <vector>

#define private public
#define protected public
#include "media_assets_controller_service.h"
#undef private
#undef protected

#include "message_parcel.h"
#include "user_define_ipc_client.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_unistore_manager.h"
#include "media_column.h"
#include "result_set_utils.h"
#include "medialibrary_errno.h"
#include "get_uri_from_filepath_vo.h"
#include "get_filepath_from_uri_vo.h"


namespace OHOS::Media {
using namespace std;
using namespace testing::ext;
using namespace OHOS::NativeRdb;

static shared_ptr<MediaLibraryRdbStore> g_rdbStore;
static constexpr int32_t SLEEP_SECONDS = 1;

static int32_t ClearTable(const string &table)
{
    RdbPredicates predicates(table);

    int32_t rows = 0;
    int32_t err = g_rdbStore->Delete(rows, predicates);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to clear album table, err: %{public}d", err);
        return E_HAS_DB_ERROR;
    }
    return E_OK;
}

void GetFilePathFromUriTest::SetUpTestCase(void)
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

void GetFilePathFromUriTest::TearDownTestCase(void)
{
    ClearTable(PhotoColumn::PHOTOS_TABLE);
    MEDIA_INFO_LOG("TearDownTestCase");
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_SECONDS));
}

void GetFilePathFromUriTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void GetFilePathFromUriTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

/**
 * @tc.name  : GetFilePathFromUriTest_ShouldReturnError_WhenReadRequestBodyFails
 * @tc.number: GetFilePathFromUriTest_001
 * @tc.desc  : 测试当读取请求体失败时,IsEdited 函数应返回错误
 */
HWTEST_F(GetFilePathFromUriTest, GetFilePathFromUriTest_001, TestSize.Level0) {
    MessageParcel data;
    MessageParcel reply;

    auto service = make_shared<MediaAssetsControllerService>();
    service->GetFilePathFromUri(data, reply);
    IPC::MediaRespVo<IPC::MediaEmptyObjVo> respVo;
    ASSERT_EQ(respVo.Unmarshalling(reply), true);
    ASSERT_LT(respVo.GetErrCode(), 0);
}


/**
 * @tc.name  : GetFilePathFromUriTest_ShouldQuerySuccessfully_WhenReadRequestBodySucceeds
 * @tc.number: GetFilePathFromUriTest_002
 * @tc.desc  : 测试当读取请求体成功时,IsEdited 函数应成功执行查询操作
 */
HWTEST_F(GetFilePathFromUriTest, GetFilePathFromUriTest_002, TestSize.Level0) {
    MessageParcel data;
    MessageParcel reply;
    GetFilePathFromUriReqBody reqBody;
    reqBody.virtualId = "12";
    auto ret = reqBody.Marshalling(data);
    EXPECT_EQ(ret, true);

    auto service = make_shared<MediaAssetsControllerService>();
    service->GetFilePathFromUri(data, reply);
    IPC::MediaRespVo<IPC::MediaEmptyObjVo> respVo;
    ret = respVo.Unmarshalling(reply);

    EXPECT_EQ(ret, true);
    EXPECT_EQ(respVo.GetErrCode(), 0);
}

/**
 * @tc.name  : GetUriFromFilePath_ShouldReturnError_WhenReadRequestBodyFails
 * @tc.number: GetUriFromFilePathTest_001
 * @tc.desc  : 测试当读取请求体失败时,GetUriFromFilePath 函数应返回错误
 */
HWTEST_F(GetFilePathFromUriTest, GetUriFromFilePath_001, TestSize.Level0) {
    MessageParcel data;
    MessageParcel reply;

    auto service = make_shared<MediaAssetsControllerService>();
    service->GetUriFromFilePath(data, reply);
    IPC::MediaRespVo<IPC::MediaEmptyObjVo> respVo;
    ASSERT_EQ(respVo.Unmarshalling(reply), true);
    ASSERT_LT(respVo.GetErrCode(), 0);
}

/**
 * @tc.name  : GetUriFromFilePath_ShouldQuerySuccessfully_WhenReadRequestBodySucceeds
 * @tc.number: GetUriFromFilePathTest_002
 * @tc.desc  : 测试当读取请求体成功时,GetUriFromFilePath 函数应成功执行查询操作
 */
HWTEST_F(GetFilePathFromUriTest, GetUriFromFilePathTest_002, TestSize.Level0) {
    MessageParcel data;
    MessageParcel reply;
    GetUriFromFilePathReqBody reqBody;
    reqBody.tempPath = "123";
    auto ret = reqBody.Marshalling(data);
    EXPECT_EQ(ret, true);

    auto service = make_shared<MediaAssetsControllerService>();
    service->GetUriFromFilePath(data, reply);
    IPC::MediaRespVo<IPC::MediaEmptyObjVo> respVo;
    ret = respVo.Unmarshalling(reply);

    EXPECT_EQ(ret, true);
    EXPECT_EQ(respVo.GetErrCode(), 0);
}
}  // namespace OHOS::Media
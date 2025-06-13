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

#include "cloud_media_change_test.h"

#include <string>
#include <vector>

#define private public
#define protected public
#include "media_assets_controller_service.h"
#undef private
#undef protected

#include "start_download_cloud_media_vo.h"
#include "retain_cloud_media_asset_vo.h"

#include "user_define_ipc_client.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_unistore_manager.h"

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

void CloudMediaChangeTest::SetUpTestCase(void)
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

void CloudMediaChangeTest::TearDownTestCase(void)
{
    ClearTable(PhotoColumn::PHOTOS_TABLE);
    MEDIA_INFO_LOG("TearDownTestCase");
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_SECONDS));
}

void CloudMediaChangeTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void CloudMediaChangeTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

HWTEST_F(CloudMediaChangeTest, StartDownloadCloudMedia_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start StartDownloadCloudMedia_Test_001");
    MessageParcel data;
    MessageParcel reply;
    StartDownloadCloudMediaReqBody reqBody;
    reqBody.cloudMediaType = 0;
    auto ret = reqBody.Marshalling(data);
    EXPECT_EQ(ret, true);

    auto service = make_shared<MediaAssetsControllerService>();
    service->StartDownloadCloudMedia(data, reply);

    IPC::MediaRespVo<IPC::MediaEmptyObjVo> respVo;
    ret = respVo.Unmarshalling(reply);
    EXPECT_EQ(true, ret);
}

HWTEST_F(CloudMediaChangeTest, StartDownloadCloudMedia_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start StartDownloadCloudMedia_Test_002");
    MessageParcel data;
    MessageParcel reply;
    StartDownloadCloudMediaReqBody reqBody;
    reqBody.cloudMediaType = 1;
    auto ret = reqBody.Marshalling(data);
    EXPECT_EQ(ret, true);

    auto service = make_shared<MediaAssetsControllerService>();
    service->StartDownloadCloudMedia(data, reply);

    IPC::MediaRespVo<IPC::MediaEmptyObjVo> respVo;
    ret = respVo.Unmarshalling(reply);
    EXPECT_EQ(true, ret);
}

HWTEST_F(CloudMediaChangeTest, StartDownloadCloudMedia_Test_003, TestSize.Level0) {
    MessageParcel data;
    MessageParcel reply;

    auto service = make_shared<MediaAssetsControllerService>();
    service->StartDownloadCloudMedia(data, reply);
    IPC::MediaRespVo<IPC::MediaEmptyObjVo> respVo;
    ASSERT_EQ(respVo.Unmarshalling(reply), true);
    ASSERT_LT(respVo.GetErrCode(), 0);
}

HWTEST_F(CloudMediaChangeTest, PauseDownloadCloudMedia_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start PauseDownloadCloudMedia_Test_001");
    MessageParcel data;
    MessageParcel reply;

    auto service = make_shared<MediaAssetsControllerService>();
    service->PauseDownloadCloudMedia(data, reply);

    IPC::MediaRespVo<IPC::MediaEmptyObjVo> respVo;
    auto ret = respVo.Unmarshalling(reply);
    EXPECT_EQ(true, ret);
}

HWTEST_F(CloudMediaChangeTest, CancelDownloadCloudMedia_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CancelDownloadCloudMedia_Test_001");
    MessageParcel data;
    MessageParcel reply;

    auto service = make_shared<MediaAssetsControllerService>();
    service->CancelDownloadCloudMedia(data, reply);

    IPC::MediaRespVo<IPC::MediaEmptyObjVo> respVo;
    auto ret = respVo.Unmarshalling(reply);
    EXPECT_EQ(true, ret);
}

HWTEST_F(CloudMediaChangeTest, RetainCloudMediaAsset_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start RetainCloudMediaAsset_Test_001");
    MessageParcel data;
    MessageParcel reply;
    RetainCloudMediaAssetReqBody reqBody;
    reqBody.cloudMediaRetainType = 0;
    auto ret = reqBody.Marshalling(data);
    EXPECT_EQ(ret, true);


    auto service = make_shared<MediaAssetsControllerService>();
    service->RetainCloudMediaAsset(data, reply);

    IPC::MediaRespVo<IPC::MediaEmptyObjVo> respVo;
    ret = respVo.Unmarshalling(reply);
    EXPECT_EQ(true, ret);
}

HWTEST_F(CloudMediaChangeTest, RetainCloudMediaAsset_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start RetainCloudMediaAsset_Test_002");
    MessageParcel data;
    MessageParcel reply;
    RetainCloudMediaAssetReqBody reqBody;
    reqBody.cloudMediaRetainType = 1;
    auto ret = reqBody.Marshalling(data);
    EXPECT_EQ(ret, true);


    auto service = make_shared<MediaAssetsControllerService>();
    service->RetainCloudMediaAsset(data, reply);

    IPC::MediaRespVo<IPC::MediaEmptyObjVo> respVo;
    ret = respVo.Unmarshalling(reply);
    EXPECT_EQ(true, ret);
}

HWTEST_F(CloudMediaChangeTest, RetainCloudMediaAsset_Test_003, TestSize.Level0) {
    MessageParcel data;
    MessageParcel reply;

    auto service = make_shared<MediaAssetsControllerService>();
    service->RetainCloudMediaAsset(data, reply);
    IPC::MediaRespVo<IPC::MediaEmptyObjVo> respVo;
    ASSERT_EQ(respVo.Unmarshalling(reply), true);
    ASSERT_LT(respVo.GetErrCode(), 0);
}
}  // namespace OHOS::Media
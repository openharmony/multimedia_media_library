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

#include "create_asset_test.h"

#include <string>
#include <vector>

#define private public
#define protected public
#include "media_assets_controller_service.h"
#undef private
#undef protected

#include "create_asset_vo.h"
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

void CreateAssetTest::SetUpTestCase(void)
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

void CreateAssetTest::TearDownTestCase(void)
{
    ClearTable(PhotoColumn::PHOTOS_TABLE);
    MEDIA_INFO_LOG("TearDownTestCase");
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_SECONDS));
}

void CreateAssetTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void CreateAssetTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

static bool CheckAsset(int32_t assetId)
{
    int32_t count = 0;
    NativeRdb::RdbPredicates rdbPredicate(PhotoColumn::PHOTOS_TABLE);
    rdbPredicate.EqualTo(PhotoColumn::MEDIA_ID, assetId);
    vector<string> columns = { PhotoColumn::MEDIA_ID };
    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicate, columns);
    if (resultSet != nullptr) {
        resultSet->GetRowCount(count);
        resultSet->Close();
    }
    return count == 1;
}

static bool CheckAlbum(int32_t albumId)
{
    int32_t count = 0;
    NativeRdb::RdbPredicates rdbPredicate(PhotoAlbumColumns::TABLE);
    rdbPredicate.EqualTo(PhotoAlbumColumns::ALBUM_ID, albumId);
    vector<string> columns = { PhotoAlbumColumns::ALBUM_ID };
    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicate, columns);
    if (resultSet != nullptr) {
        resultSet->GetRowCount(count);
        resultSet->Close();
    }
    return count == 1;
}

static int32_t GetAlbumId(const std::string &albumName)
{
    NativeRdb::RdbPredicates rdbPredicate(PhotoAlbumColumns::TABLE);
    rdbPredicate.EqualTo(PhotoAlbumColumns::ALBUM_NAME, albumName);
    vector<string> columns = { PhotoAlbumColumns::ALBUM_ID };
    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicate, columns);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Query failed, albumName:%{public}s", albumName.c_str());
        return 0;
    }
    int32_t albumId = 0;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        albumId = MediaLibraryRdbStore::GetInt(resultSet, PhotoAlbumColumns::ALBUM_ID);
        MEDIA_INFO_LOG("resultSet: albumId:%{public}d, albumName:%{public}s", albumId, albumName.c_str());
    }
    resultSet->Close();
    return albumId;
}

using ServiceCall = std::function<void(MessageParcel &data, MessageParcel &reply)>;

int32_t ServiceCreateAsset(CreateAssetReqBody &reqBody, ServiceCall call)
{
    MessageParcel data;
    if (reqBody.Marshalling(data) != true) {
        MEDIA_ERR_LOG("reqBody.Marshalling failed");
        return -1;
    }

    MessageParcel reply;
    call(data, reply);

    IPC::MediaRespVo<CreateAssetRspBody> respVo;
    if (respVo.Unmarshalling(reply) != true) {
        MEDIA_ERR_LOG("respVo.Unmarshalling failed");
        return -1;
    }

    int32_t errCode = respVo.GetErrCode();
    if (errCode != 0) {
        MEDIA_ERR_LOG("respVo.GetErrCode: %{public}d", errCode);
        return errCode;
    }

    return respVo.GetBody().fileId;
}

int32_t ServiceCreateAssetForApp(CreateAssetForAppReqBody &reqBody, ServiceCall call)
{
    MessageParcel data;
    if (reqBody.Marshalling(data) != true) {
        MEDIA_ERR_LOG("reqBody.Marshalling failed");
        return -1;
    }

    MessageParcel reply;
    call(data, reply);

    IPC::MediaRespVo<CreateAssetForAppRspBody> respVo;
    if (respVo.Unmarshalling(reply) != true) {
        MEDIA_ERR_LOG("respVo.Unmarshalling failed");
        return -1;
    }

    int32_t errCode = respVo.GetErrCode();
    if (errCode != 0) {
        MEDIA_ERR_LOG("respVo.GetErrCode: %{public}d", errCode);
        return errCode;
    }

    return respVo.GetBody().fileId;
}

int32_t PublicCreateAsset(const std::string &ext, const std::string &title = "")
{
    CreateAssetReqBody reqBody;
    reqBody.mediaType = MEDIA_TYPE_IMAGE;
    reqBody.title = title;
    reqBody.extension = ext;

    ServiceCall call = [](MessageParcel &data, MessageParcel &reply) {
        auto service = make_shared<MediaAssetsControllerService>();
        service->PublicCreateAsset(data, reply);
    };

    return ServiceCreateAsset(reqBody, call);
}

int32_t SystemCreateAsset(const std::string &displayName, int32_t photoSubtype, const std::string &cameraShotKey = "")
{
    CreateAssetReqBody reqBody;
    reqBody.mediaType = MEDIA_TYPE_IMAGE;
    reqBody.photoSubtype = photoSubtype;
    reqBody.displayName = displayName;
    reqBody.cameraShotKey = cameraShotKey;

    ServiceCall call = [](MessageParcel &data, MessageParcel &reply) {
        auto service = make_shared<MediaAssetsControllerService>();
        service->SystemCreateAsset(data, reply);
    };

    return ServiceCreateAsset(reqBody, call);
}

int32_t PublicCreateAssetForApp(int32_t tokenId, const std::string &ext, const std::string &title = "")
{
    CreateAssetForAppReqBody reqBody;
    reqBody.tokenId = tokenId;
    reqBody.mediaType = MEDIA_TYPE_IMAGE;
    reqBody.photoSubtype = static_cast<int32_t>(PhotoSubType::DEFAULT);
    reqBody.title = title;
    reqBody.extension = ext;
    reqBody.appId = "unittest";
    reqBody.packageName = "media_assets_controler_service_test";
    reqBody.bundleName = "create_asset_test.cpp";

    ServiceCall call = [](MessageParcel &data, MessageParcel &reply) {
        auto service = make_shared<MediaAssetsControllerService>();
        service->PublicCreateAssetForApp(data, reply);
    };

    return ServiceCreateAssetForApp(reqBody, call);
}

int32_t SystemCreateAssetForApp(int32_t tokenId, const std::string &ext, const std::string &title = "")
{
    CreateAssetForAppReqBody reqBody;
    reqBody.tokenId = tokenId;
    reqBody.mediaType = MEDIA_TYPE_IMAGE;
    reqBody.photoSubtype = static_cast<int32_t>(PhotoSubType::DEFAULT);
    reqBody.title = title;
    reqBody.extension = ext;
    reqBody.appId = "unittest";
    reqBody.packageName = "media_assets_controler_service_test";
    reqBody.bundleName = "create_asset_test.cpp";

    ServiceCall call = [](MessageParcel &data, MessageParcel &reply) {
        auto service = make_shared<MediaAssetsControllerService>();
        service->SystemCreateAssetForApp(data, reply);
    };

    return ServiceCreateAssetForApp(reqBody, call);
}

int32_t CreateAssetForAppWithAlbum(int32_t tokenId, int32_t albumId,
    const std::string &ext, const std::string &title = "")
{
    CreateAssetForAppReqBody reqBody;
    reqBody.tokenId = tokenId;
    reqBody.mediaType = MEDIA_TYPE_IMAGE;
    reqBody.photoSubtype = static_cast<int32_t>(PhotoSubType::DEFAULT);
    reqBody.title = title;
    reqBody.extension = ext;
    reqBody.appId = "unittest";
    reqBody.packageName = "media_assets_controler_service_test";
    reqBody.bundleName = "create_asset_test.cpp";
    reqBody.ownerAlbumId = to_string(albumId);

    ServiceCall call = [](MessageParcel &data, MessageParcel &reply) {
        auto service = make_shared<MediaAssetsControllerService>();
        service->CreateAssetForAppWithAlbum(data, reply);
    };

    return ServiceCreateAssetForApp(reqBody, call);
}

HWTEST_F(CreateAssetTest, PublicCreateAsset_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start PublicCreateAsset_Test_001");
    int32_t fileId = PublicCreateAsset("xxx");
    ASSERT_LT(fileId, 0);

    fileId = PublicCreateAsset("jpg", "Public_002.xxx");
    ASSERT_LT(fileId, 0);
}

HWTEST_F(CreateAssetTest, PublicCreateAsset_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start PublicCreateAsset_Test_002");
    int32_t fileId = PublicCreateAsset("jpg");
    ASSERT_GT(fileId, 0);
    bool hasAsset = CheckAsset(fileId);
    ASSERT_EQ(hasAsset, true);

    fileId = PublicCreateAsset("jpg", "Public_002");
    ASSERT_GT(fileId, 0);
    hasAsset = CheckAsset(fileId);
    ASSERT_EQ(hasAsset, true);
}

HWTEST_F(CreateAssetTest, SystemCreateAsset_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start SystemCreateAsset_Test_001");
    int32_t fileId = SystemCreateAsset("System_001.jpg",
        static_cast<int32_t>(PhotoSubType::DEFAULT), "SystemCreateAsset_Test_001");
    ASSERT_LT(fileId, 0);

    fileId = SystemCreateAsset("System_001.jpg",
        static_cast<int32_t>(PhotoSubType::SCREENSHOT), "SystemCreateAsset_Test_001AAAAAA");
    ASSERT_LT(fileId, 0);
}

HWTEST_F(CreateAssetTest, SystemCreateAsset_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start SystemCreateAsset_Test_002");
    int32_t fileId = SystemCreateAsset("System_002.jpg", static_cast<int32_t>(PhotoSubType::DEFAULT));
    ASSERT_GT(fileId, 0);
    bool hasAsset = CheckAsset(fileId);
    ASSERT_EQ(hasAsset, true);

    fileId = SystemCreateAsset("System_002.jpg",
        static_cast<int32_t>(PhotoSubType::DEFAULT), "SystemCreateAsset_Test_001AAAAAA");
    ASSERT_GT(fileId, 0);
    hasAsset = CheckAsset(fileId);
    ASSERT_EQ(hasAsset, true);

    fileId = SystemCreateAsset("System.002.jpg",
        static_cast<int32_t>(PhotoSubType::DEFAULT), "SystemCreateAsset_Test_001AAAAAA");
    ASSERT_GT(fileId, 0);
    hasAsset = CheckAsset(fileId);
    ASSERT_EQ(hasAsset, true);
}

HWTEST_F(CreateAssetTest, PublicCreateAssetForApp_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start PublicCreateAssetForApp_Test_001");
    int32_t fileId = PublicCreateAssetForApp(0, "xxx");
    ASSERT_LT(fileId, 0);

    fileId = PublicCreateAssetForApp(0, "jpg", "ForApp_001.xxx");
    ASSERT_LT(fileId, 0);
}

HWTEST_F(CreateAssetTest, PublicCreateAssetForApp_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start PublicCreateAssetForApp_Test_002");
    int32_t fileId = PublicCreateAssetForApp(0, "jpg");
    ASSERT_GT(fileId, 0);
    bool hasAsset = CheckAsset(fileId);
    ASSERT_EQ(hasAsset, true);

    fileId = PublicCreateAssetForApp(0, "jpg", "ForApp_002");
    ASSERT_GT(fileId, 0);
    hasAsset = CheckAsset(fileId);
    ASSERT_EQ(hasAsset, true);
}

HWTEST_F(CreateAssetTest, SystemCreateAssetForApp_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start SystemCreateAssetForApp_Test_001");
    int32_t fileId = SystemCreateAssetForApp(0, "xxx");
    ASSERT_LT(fileId, 0);

    fileId = SystemCreateAssetForApp(0, "jpg", "ForApp_001?xxx");
    ASSERT_LT(fileId, 0);
}

HWTEST_F(CreateAssetTest, SystemCreateAssetForApp_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start SystemCreateAssetForApp_Test_002");
    int32_t fileId = SystemCreateAssetForApp(0, "jpg");
    ASSERT_GT(fileId, 0);
    bool hasAsset = CheckAsset(fileId);
    ASSERT_EQ(hasAsset, true);

    fileId = SystemCreateAssetForApp(0, "jpg", "ForApp_002");
    ASSERT_GT(fileId, 0);
    hasAsset = CheckAsset(fileId);
    ASSERT_EQ(hasAsset, true);

    fileId = SystemCreateAssetForApp(0, "jpg", "ForApp_002.xxx");
    ASSERT_GT(fileId, 0);
    hasAsset = CheckAsset(fileId);
    ASSERT_EQ(hasAsset, true);
}

HWTEST_F(CreateAssetTest, CreateAssetForAppWithAlbum_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CreateAssetForAppWithAlbum_Test_001");
    int32_t fileId = CreateAssetForAppWithAlbum(0, 0, "xxx");
    ASSERT_LT(fileId, 0);

    fileId = CreateAssetForAppWithAlbum(0, 0, "jpg");
    ASSERT_LT(fileId, 0);

    fileId = CreateAssetForAppWithAlbum(0, 0, "jpg", "WithAlbum_001?xxx");
    ASSERT_LT(fileId, 0);

    fileId = CreateAssetForAppWithAlbum(0, 0, "jpg", "WithAlbum_001");
    ASSERT_LT(fileId, 0);
}

HWTEST_F(CreateAssetTest, CreateAssetForAppWithAlbum_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CreateAssetForAppWithAlbum_Test_002");
    int32_t albumId = GetAlbumId("media_assets_controler_service_test");
    ASSERT_GT(albumId, 0);

    int32_t fileId = CreateAssetForAppWithAlbum(0, albumId, "jpg");
    ASSERT_GT(fileId, 0);
    bool hasAsset = CheckAsset(fileId);
    ASSERT_EQ(hasAsset, true);

    fileId = CreateAssetForAppWithAlbum(0, albumId, "jpg", "WithAlbum_002");
    ASSERT_GT(fileId, 0);
    hasAsset = CheckAsset(fileId);
    ASSERT_EQ(hasAsset, true);

    fileId = CreateAssetForAppWithAlbum(0, albumId, "jpg", "WithAlbum_002.xxx");
    ASSERT_GT(fileId, 0);
    hasAsset = CheckAsset(fileId);
    ASSERT_EQ(hasAsset, true);
}

}  // namespace OHOS::Media
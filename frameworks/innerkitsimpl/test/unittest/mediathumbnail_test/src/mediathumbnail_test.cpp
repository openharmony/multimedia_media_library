/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "mediathumbnail_test.h"

#include <unistd.h>

#include "datashare_helper.h"
#include "get_self_permissions.h"
#include "iservice_registry.h"
#include "medialibrary_db_const.h"
#include "media_log.h"
#include "media_thumbnail_helper.h"
#include "scanner_utils.h"
#include "result_set_utils.h"

using namespace std;
using namespace OHOS::NativeRdb;
using namespace testing::ext;

namespace OHOS {
namespace Media {
constexpr int STORAGE_MANAGER_MANAGER_ID = 5003;
const int32_t PARAM1 = 1;
std::shared_ptr<MediaThumbnailHelper> g_thumbnailHelper = nullptr;
std::shared_ptr<DataShare::DataShareHelper> g_mediaDataShareHelper = nullptr;

std::shared_ptr<DataShare::DataShareHelper> CreateDataHelper(int32_t systemAbilityId)
{
    MEDIA_INFO_LOG("DataMedialibraryRdbHelper::CreateDataHelper ");
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        MEDIA_INFO_LOG("DataMedialibraryRdbHelper::CreateDataHelper Get system ability mgr failed.");
        return nullptr;
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    while (remoteObj == nullptr) {
        MEDIA_INFO_LOG("DataMedialibraryRdbHelper::CreateDataHelper GetSystemAbility Service Failed.");
        return nullptr;
    }
    return DataShare::DataShareHelper::Creator(remoteObj, MEDIALIBRARY_DATA_URI);
}

void MediaThumbnailTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase invoked");
    vector<string> perms;
    perms.push_back("ohos.permission.READ_MEDIA");
    perms.push_back("ohos.permission.WRITE_MEDIA");
    perms.push_back("ohos.permission.FILE_ACCESS_MANAGER");
    perms.push_back("ohos.permission.GET_BUNDLE_INFO_PRIVILEGED");
    uint64_t tokenId = 0;
    PermissionUtilsUnitTest::SetAccessTokenPermission("MediaThumbnailUnitTest", perms, tokenId);
    ASSERT_TRUE(tokenId != 0);

    g_thumbnailHelper = std::make_shared<MediaThumbnailHelper>();
    g_mediaDataShareHelper = CreateDataHelper(STORAGE_MANAGER_MANAGER_ID);
    if (g_mediaDataShareHelper == nullptr) {
        MEDIA_ERR_LOG("SetUpTestCase::DataShareHelper == nullptr");
        return;
    }
}

void MediaThumbnailTest::TearDownTestCase(void) { }

void MediaThumbnailTest::SetUp(void) { }

void MediaThumbnailTest::TearDown(void) { }

bool GetFileAsset(unique_ptr<FileAsset> &fileAsset, string displayName)
{
    if (g_mediaDataShareHelper == nullptr) {
        MEDIA_ERR_LOG("GetFileAsset::DataShareHelper == nullptr");
        return false;
    }
    vector<string> columns;
    DataShare::DataSharePredicates predicates;
    string selections = MEDIA_DATA_DB_NAME + " = ? ";
    vector<string> selectionArgs = { displayName };
    predicates.SetWhereClause(selections);
    predicates.SetWhereArgs(selectionArgs);
    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    auto resultSet = g_mediaDataShareHelper->Query(queryFileUri, predicates, columns);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("GetFileAsset::resultSet == nullptr");
        return false;
    }

    // Create FetchResult object using the contents of resultSet
    unique_ptr<FetchResult<FileAsset>> fetchFileResult = make_unique<FetchResult<FileAsset>>(move(resultSet));
    if (fetchFileResult->GetCount() <= 0) {
        MEDIA_ERR_LOG("GetFileAsset::GetCount <= 0");
        return false;
    }

    fileAsset = fetchFileResult->GetFirstObject();
    if (fileAsset == nullptr) {
        MEDIA_ERR_LOG("GetFileAsset::fileAsset = nullptr.");
        return false;
    }
    return true;
}

static bool ParseThumbnailResult(int32_t file_id, std::string &thumbnailKey, std::string &lcdKey)
{
    if (g_mediaDataShareHelper == nullptr) {
        MEDIA_ERR_LOG("GetFileAsset::DataShareHelper == nullptr");
        return false;
    }
    vector<string> columns;
    DataShare::DataSharePredicates predicates;
    string selections = MEDIA_DATA_DB_ID + " = ? ";
    vector<string> selectionArgs = { to_string(file_id) };
    predicates.SetWhereClause(selections);
    predicates.SetWhereArgs(selectionArgs);
    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    auto resultSet = g_mediaDataShareHelper->Query(queryFileUri, predicates, columns);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("GetFileAsset::resultSet == nullptr");
        return false;
    }
    int rowCount = 0;
    resultSet->GetRowCount(rowCount);
    if (rowCount <= 0) {
        return false;
    }
    if (resultSet->GoToFirstRow() != E_OK) {
        return false;
    }
    thumbnailKey = get<string>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_THUMBNAIL, resultSet, TYPE_STRING));
    lcdKey = get<string>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_LCD, resultSet, TYPE_STRING));
    return true;
}

shared_ptr<DataShare::DataShareResultSet> QueryThumbnail(const string &uri, Size size)
{
    Uri queryUri(uri + "?" +
                 Media::MEDIA_OPERN_KEYWORD + "=" + Media::MEDIA_DATA_DB_THUMBNAIL + "&" +
                 Media::MEDIA_DATA_DB_WIDTH + "=" + to_string(size.width) + "&" +
                 Media::MEDIA_DATA_DB_HEIGHT + "=" + to_string(size.height));
    if (g_mediaDataShareHelper == nullptr) {
        MEDIA_ERR_LOG("CreateImageThumbnailTest_001:: DataShareHelper == nullptr");
        return nullptr;
    }
    DataShare::DataSharePredicates predicates;
    std::vector<std::string> columns;
    MEDIA_DEBUG_LOG("CreateImageThumbnailTest_001:: Start gen thumbnail key");
    return g_mediaDataShareHelper->Query(queryUri, predicates, columns);
}

HWTEST_F(MediaThumbnailTest, ResizeImage_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("CreateImageThumbnailTest_001:: Start");
    string displayName = "CreateImageThumbnailTest_001.jpg";
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!GetFileAsset(fileAsset, displayName)) {
        return;
    }

    Size size = {
        .width = 256, .height = 256
    };
    shared_ptr<DataShare::DataShareResultSet> resultSet = QueryThumbnail(fileAsset->GetUri(), size);
    if (resultSet == nullptr) {
        EXPECT_EQ(true, false);
        return;
    }
    resultSet->GoToFirstRow();
    vector<uint8_t> TEST_DATA;
    unique_ptr<PixelMap> pixelMap;
    MediaThumbnailHelper::ResizeImage(TEST_DATA, size, pixelMap);
    TEST_DATA.push_back(1);
    MediaThumbnailHelper::ResizeImage(TEST_DATA, size, pixelMap);
    EXPECT_EQ(pixelMap, nullptr);

    vector<uint8_t> image;
    resultSet->GetBlob(PARAM1, image);
    resultSet->Close();
    Size TEST_SIZE = {
        .width = PIXEL_MAP_MAX_RAM_SIZE, .height = PIXEL_MAP_MAX_RAM_SIZE
    };
    MediaThumbnailHelper::ResizeImage(image, TEST_SIZE, pixelMap);
    EXPECT_EQ(pixelMap, nullptr);
}

HWTEST_F(MediaThumbnailTest, CreateImageThumbnailTest_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("CreateImageThumbnailTest_001:: Start");
    string displayName = "CreateImageThumbnailTest_001.jpg";
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!GetFileAsset(fileAsset, displayName)) {
        return;
    }

    Size size = {
        .width = 256, .height = 256
    };
    shared_ptr<DataShare::DataShareResultSet> resultSet = QueryThumbnail(fileAsset->GetUri(), size);
    if (resultSet == nullptr) {
        EXPECT_EQ(true, false);
        return;
    }
    resultSet->GoToFirstRow();
    vector<uint8_t> image;
    unique_ptr<PixelMap> pixelMap;
    MediaThumbnailHelper::ResizeImage(image, size, pixelMap);
    resultSet->GetBlob(PARAM1, image);
    resultSet->Close();
    MediaThumbnailHelper::ResizeImage(image, size, pixelMap);
    EXPECT_NE(pixelMap, nullptr);
    if (pixelMap) {
        EXPECT_EQ(pixelMap->GetWidth(), size.width);
        EXPECT_EQ(pixelMap->GetHeight(), size.height);
    }

    string thumbnailKey, lcdKey;
    if (!ParseThumbnailResult(fileAsset->GetId(), thumbnailKey, lcdKey)) {
        MEDIA_ERR_LOG("CreateImageThumbnailTest_001:: ParseThumbnailResult failed");
        EXPECT_EQ(true, false);
        return;
    }
    EXPECT_NE(thumbnailKey.empty(), true);
    EXPECT_EQ(lcdKey.empty(), true);
}

HWTEST_F(MediaThumbnailTest, CreateImageLcdTest_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("CreateImageLcdTest_001:: Start");
    string displayName = "CreateImageLcdTest_001.jpg";
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!GetFileAsset(fileAsset, displayName)) {
        return;
    }

    Size size1 = {
        .width = 256, .height = 256
    };
    shared_ptr<DataShare::DataShareResultSet> resultSet1 = QueryThumbnail(fileAsset->GetUri(), size1);
    if (resultSet1 == nullptr) {
        EXPECT_EQ(true, false);
        return;
    }
    Size size2 = {
        .width = 472, .height = 226
    };
    shared_ptr<DataShare::DataShareResultSet> resultSet = QueryThumbnail(fileAsset->GetUri(), size2);
    if (resultSet == nullptr) {
        EXPECT_EQ(true, false);
        return;
    }
    resultSet->GoToFirstRow();
    vector<uint8_t> image;
    resultSet->GetBlob(PARAM1, image);
    resultSet->Close();
    unique_ptr<PixelMap> pixelMap;
    MediaThumbnailHelper::ResizeImage(image, size2, pixelMap);
    EXPECT_NE(pixelMap, nullptr);
    if (pixelMap) {
        EXPECT_EQ(pixelMap->GetWidth(), size2.width);
        EXPECT_EQ(pixelMap->GetHeight(), size2.height);
    }

    string thumbnailKey, lcdKey;
    if (!ParseThumbnailResult(fileAsset->GetId(), thumbnailKey, lcdKey)) {
        MEDIA_ERR_LOG("CreateImageLcdTest_001:: ParseThumbnailResult failed");
        EXPECT_EQ(true, false);
        return;
    }
    EXPECT_NE(thumbnailKey.empty(), true);
    EXPECT_NE(lcdKey.empty(), true);
}

HWTEST_F(MediaThumbnailTest, CreateAudioThumbnailTest_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("CreateAudioThumbnailTest_001:: Start");
    string displayName = "CreateAudioThumbnailTest_001.mp3";
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!GetFileAsset(fileAsset, displayName)) {
        return;
    }

    Size size = {
        .width = 256, .height = 256
    };
    shared_ptr<DataShare::DataShareResultSet> resultSet = QueryThumbnail(fileAsset->GetUri(), size);
    if (resultSet == nullptr) {
        EXPECT_EQ(true, false);
        return;
    }
    resultSet->GoToFirstRow();
    vector<uint8_t> image;
    resultSet->GetBlob(PARAM1, image);
    resultSet->Close();
    unique_ptr<PixelMap> pixelMap;
    MediaThumbnailHelper::ResizeImage(image, size, pixelMap);
    EXPECT_NE(pixelMap, nullptr);
    if (pixelMap) {
        EXPECT_EQ(pixelMap->GetWidth(), size.width);
        EXPECT_EQ(pixelMap->GetHeight(), size.height);
    }

    string thumbnailKey, lcdKey;
    if (!ParseThumbnailResult(fileAsset->GetId(), thumbnailKey, lcdKey)) {
        MEDIA_ERR_LOG("CreateAudioThumbnailTest_001:: ParseThumbnailResult failed");
        EXPECT_EQ(true, false);
        return;
    }
    EXPECT_NE(thumbnailKey.empty(), true);
    EXPECT_EQ(lcdKey.empty(), true);
}

HWTEST_F(MediaThumbnailTest, CreateVideoThumbnailTest_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("CreateVideoThumbnailTest_001:: Start");
    string displayName = "CreateVideoThumbnailTest_001.mp4";
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!GetFileAsset(fileAsset, displayName)) {
        return;
    }

    Size size = {
        .width = 256, .height = 256
    };
    shared_ptr<DataShare::DataShareResultSet> resultSet = QueryThumbnail(fileAsset->GetUri(), size);
    if (resultSet == nullptr) {
        EXPECT_EQ(true, false);
        return;
    }
    resultSet->GoToFirstRow();
    vector<uint8_t> image;
    resultSet->GetBlob(PARAM1, image);
    resultSet->Close();
    unique_ptr<PixelMap> pixelMap;
    MediaThumbnailHelper::ResizeImage(image, size, pixelMap);
    EXPECT_NE(pixelMap, nullptr);
    if (pixelMap) {
        EXPECT_EQ(pixelMap->GetWidth(), size.width);
        EXPECT_EQ(pixelMap->GetHeight(), size.height);
    }

    string thumbnailKey, lcdKey;
    if (!ParseThumbnailResult(fileAsset->GetId(), thumbnailKey, lcdKey)) {
        MEDIA_ERR_LOG("CreateVideoThumbnailTest_001:: ParseThumbnailResult failed");
        EXPECT_EQ(true, false);
        return;
    }
    EXPECT_NE(thumbnailKey.empty(), true);
    EXPECT_EQ(lcdKey.empty(), true);
}
} // namespace Media
} // namespace OHOS

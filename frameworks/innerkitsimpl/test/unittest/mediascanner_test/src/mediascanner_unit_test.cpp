/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#include "datashare_helper.h"
#include "fetch_result.h"
#include "get_self_permissions.h"
#include "iservice_registry.h"
#include "medialibrary_errno.h"
#include "mediascanner_unit_test.h"
#include "media_file_utils.h"
#include "media_library_manager.h"
#include "media_log.h"
#include "media_scanner_manager.h"
#include "system_ability_definition.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace {
    string g_prefixPath = "/storage/media/local/files";
    const mode_t CHOWN_RW_UG = 0660;
}
constexpr int STORAGE_MANAGER_MANAGER_ID = 5003;
std::shared_ptr<DataShare::DataShareHelper> g_mediaDataShareHelper;

std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper(int32_t systemAbilityId)
{
    MEDIA_INFO_LOG("CreateDataShareHelper::CreateFileExtHelper ");
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        MEDIA_INFO_LOG("CreateDataShareHelper::CreateFileExtHelper Get system ability mgr failed.");
        return nullptr;
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    while (remoteObj == nullptr) {
        MEDIA_INFO_LOG("CreateDataShareHelper::CreateFileExtHelper GetSystemAbility Service Failed.");
        return nullptr;
    }
    return DataShare::DataShareHelper::Creator(remoteObj, MEDIALIBRARY_DATA_URI);
}
bool CreateFile(const string &filePath)
{
    bool errCode = false;

    if (filePath.empty()) {
        return errCode;
    }

    ofstream file(filePath);
    if (!file) {
        MEDIA_ERR_LOG("Output file path could not be created");
        return errCode;
    }

    if (chmod(filePath.c_str(), CHOWN_RW_UG) == 0) {
        errCode = true;
    }

    file.close();

    return errCode;
}

void MediaScannerUnitTest::SetUpTestCase(void)
{
    vector<string> perms;
    perms.push_back("ohos.permission.READ_MEDIA");
    perms.push_back("ohos.permission.WRITE_MEDIA");
    perms.push_back("ohos.permission.FILE_ACCESS_MANAGER");
    uint64_t tokenId = 0;
    PermissionUtilsUnitTest::SetAccessTokenPermission("MediaDataShareUnitTest", perms, tokenId);
    ASSERT_TRUE(tokenId != 0);

    MEDIA_INFO_LOG("SetUpTestCase invoked");
    g_mediaDataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_TRUE(g_mediaDataShareHelper != nullptr);

    Uri deleteAssetUri(MEDIALIBRARY_DATA_URI);
    DataShare::DataSharePredicates predicates;
    string selections = MEDIA_DATA_DB_ID + " <> 0 ";
    predicates.SetWhereClause(selections);
    int retVal = g_mediaDataShareHelper->Delete(deleteAssetUri, predicates);
    MEDIA_INFO_LOG("SetUpTestCase Delete retVal: %{public}d", retVal);
    EXPECT_EQ((retVal >= 0), true);
}

void MediaScannerUnitTest::TearDownTestCase(void) {}
string ConvertPath(string path)
{
    string tmp = "/storage/media/100/";
    path = tmp + path.substr(strlen("/storage/media/"));
    return path;
}
void MediaScannerUnitTest::SetUp(void) {}
void MediaScannerUnitTest::TearDown(void) {}

/*
 * Feature: MediaScanner
 * Function: Scan a directory with media files
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerUnitTest,  mediascanner_ScanDir_test_001, TestSize.Level0)
{
    Uri scanUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_BOARDCASTOPRN);
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_FILE_PATH, ROOT_MEDIA_DIR);
    auto ret = g_mediaDataShareHelper->Insert(scanUri, valuesBucket);
    EXPECT_EQ(ret, E_SUCCESS);
}

/*
 * Feature : MediaScannerUnitTest
 * Function : Scan a jpg image file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerUnitTest, mediascanner_ScanImage_Test_001, TestSize.Level0)
{
    bool createRes = CreateFile("/storage/media/100/local/files/Pictures/gtest_Image1.jpg");
    EXPECT_EQ(createRes, true);

    Uri scanUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_BOARDCASTOPRN);
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_FILE_PATH, ROOT_MEDIA_DIR);
    auto ret = g_mediaDataShareHelper->Insert(scanUri, valuesBucket);
    EXPECT_EQ(ret, E_SUCCESS);
}

/*
 * Feature : MediaScannerUnitTest
 * Function : Scan a png image file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerUnitTest, mediascanner_ScanImage_Test_002, TestSize.Level0)
{
    bool createRes = CreateFile("/storage/media/100/local/files/Pictures/gtest_Image2.png");
    EXPECT_EQ(createRes, true);

    Uri scanUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_BOARDCASTOPRN);
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_FILE_PATH, ROOT_MEDIA_DIR);
    auto ret = g_mediaDataShareHelper->Insert(scanUri, valuesBucket);
    EXPECT_EQ(ret, E_SUCCESS);
}

/*
 * Feature : MediaScannerUnitTest
 * Function : Scan an audio file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerUnitTest, mediascanner_ScanImage_Test_003, TestSize.Level0)
{
    bool createRes = CreateFile("/storage/media/100/local/files/Pictures/gtest_Image3.jpeg");
    EXPECT_EQ(createRes, true);

    Uri scanUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_BOARDCASTOPRN);
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_FILE_PATH, ROOT_MEDIA_DIR);
    auto ret = g_mediaDataShareHelper->Insert(scanUri, valuesBucket);
    EXPECT_EQ(ret, E_SUCCESS);
}

/*
 * Feature : MediaScannerUnitTest
 * Function : Scan a normal text file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerUnitTest, mediascanner_ScanTextFile_Test_001, TestSize.Level0)
{
    bool createRes = CreateFile("/storage/media/100/local/files/Documents/gtest_Text1.txt");
    EXPECT_EQ(createRes, true);

    Uri scanUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_BOARDCASTOPRN);
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_FILE_PATH, ROOT_MEDIA_DIR);
    auto ret = g_mediaDataShareHelper->Insert(scanUri, valuesBucket);
    EXPECT_EQ(ret, E_SUCCESS);
}

/*
 * Feature : MediaScannerUnitTest
 * Function : Scan a hidden file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerUnitTest, mediascanner_ScanHiddenFile_Test_001, TestSize.Level0)
{
    bool createRes = CreateFile("/storage/media/100/local/files/Download/.HiddenFile");
    EXPECT_EQ(createRes, true);

    Uri scanUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_BOARDCASTOPRN);
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_FILE_PATH, ROOT_MEDIA_DIR);
    auto ret = g_mediaDataShareHelper->Insert(scanUri, valuesBucket);
    EXPECT_EQ(ret, E_SUCCESS);
}

/*
 * Feature: MediaScanner
 * Function: Scan a directory with image, video, audio and other type of files
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerUnitTest,  mediascanner_ScanDir_test_002, TestSize.Level0)
{
    Uri scanUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_BOARDCASTOPRN);
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_FILE_PATH, ROOT_MEDIA_DIR);
    auto ret = g_mediaDataShareHelper->Insert(scanUri, valuesBucket);
    EXPECT_EQ(ret, E_SUCCESS);
}

/*
 * Feature: MediaScanner
 * Function: Scan a directory with path provided as relative, must convert to canonical form
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerUnitTest,  mediascanner_ScanDir_CononicalPathtest_001, TestSize.Level0)
{
    Uri scanUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_BOARDCASTOPRN);
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_FILE_PATH, ROOT_MEDIA_DIR);
    auto ret = g_mediaDataShareHelper->Insert(scanUri, valuesBucket);
    EXPECT_EQ(ret, E_SUCCESS);
}

/*
 * Feature: MediaScanner
 * Function: Scan an image file with path provided as relative, must convert to canonical form
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerUnitTest,  mediascanner_ScanFile_CononicalPathtest_001, TestSize.Level0)
{
    Uri scanUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_BOARDCASTOPRN);
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_FILE_PATH, ROOT_MEDIA_DIR);
    auto ret = g_mediaDataShareHelper->Insert(scanUri, valuesBucket);
    EXPECT_EQ(ret, E_SUCCESS);
}

/*
 * Feature: MediaScanner
 * Function: Scan a text file with path provided as relative, must convert to canonical form
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerUnitTest,  mediascanner_ScanFile_CononicalPathtest_002, TestSize.Level0)
{
    MEDIA_DEBUG_LOG("mediascanner_ScanFile_CononicalPathtest_002 start");
    Uri scanUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_BOARDCASTOPRN);
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_FILE_PATH, ROOT_MEDIA_DIR);
    auto ret = g_mediaDataShareHelper->Insert(scanUri, valuesBucket);
    EXPECT_EQ(ret, E_SUCCESS);
    MEDIA_DEBUG_LOG("mediascanner_ScanFile_CononicalPathtest_002 end");
}
} // namespace Media
} // namespace OHOS

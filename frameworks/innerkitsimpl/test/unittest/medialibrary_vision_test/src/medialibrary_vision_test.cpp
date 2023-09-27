/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#define MLOG_TAG "MediaLibraryVisionTest"

#include <stdlib.h>

#include "datashare_helper.h"
#include "get_self_permissions.h"
#include "iservice_registry.h"
#include "media_log.h"
#include "medialibrary_vision_test.h"
#include "uri.h"
#include "vision_column.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;

constexpr int STORAGE_MANAGER_MANAGER_ID = 5003;
constexpr int N = 9999;
std::shared_ptr<DataShare::DataShareHelper> g_dataShareHelper;

std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper(int32_t systemAbilityId)
{
    MEDIA_INFO_LOG("CreateDataShareHelper start");
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        MEDIA_INFO_LOG("GetSystemAbilityManager get samgr failed.");
        return nullptr;
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    while (remoteObj == nullptr) {
        MEDIA_INFO_LOG("GetSystemAbility service failed.");
        return nullptr;
    }
    return DataShare::DataShareHelper::Creator(remoteObj, MEDIALIBRARY_DATA_URI);
}

void CleanVisionData() {
    DataShare::DataSharePredicates predicates;
    Uri ocrUri(URI_OCR);
    Uri labelUri(URI_LABEL);
    Uri aesUri(URI_AESTHETICS);
    Uri shieldUri(URI_SHIELD);
    g_dataShareHelper->Delete(ocrUri, predicates);
    g_dataShareHelper->Delete(labelUri, predicates);
    g_dataShareHelper->Delete(aesUri, predicates);
    g_dataShareHelper->Delete(shieldUri, predicates);
}

int GetRand(int min, int max) {
    return rand() % (max - min + 1) + min;
}

float GetRandFloat(int min, int max) {
    float num = rand() % (N + 1) / (float)(N + 1);
	return num * (max - min) + min;
}

void InitPerformanceData() {
    Uri ocrUri(URI_OCR);
    Uri labelUri(URI_LABEL);
    Uri aesUri(URI_AESTHETICS);
    for (int i = 0; i <= 10000; i++) {
        DataShare::DataShareValuesBucket valuesBucket1;
        valuesBucket1.Put(FILE_ID, i);
        valuesBucket1.Put(OCR_TEXT, "ocrTest");
        valuesBucket1.Put(OCR_VERSION, "1.01");
        valuesBucket1.Put(OCR_TEXT_MSG, "ocrTestMsg");
        g_dataShareHelper->Insert(ocrUri, valuesBucket1);
        DataShare::DataShareValuesBucket valuesBucket2;
        valuesBucket2.Put(FILE_ID, i);
        valuesBucket2.Put(CATEGORY_ID, GetRand(0, 10));
        valuesBucket2.Put(SUB_LABEL, GetRand(0, 200));
        valuesBucket2.Put(PROB, GetRandFloat(0, 10));
        valuesBucket2.Put(LABEL_VERSION, "1.01");
        g_dataShareHelper->Insert(labelUri, valuesBucket2);
        DataShare::DataShareValuesBucket valuesBucket3;
        valuesBucket3.Put(FILE_ID, i);
        valuesBucket3.Put(AESTHETICS_SCORE, GetRand(0, 10));
        valuesBucket3.Put(AESTHETICS_VERSION, "1.01");
        valuesBucket3.Put(PROB, GetRandFloat(0, 10));
        g_dataShareHelper->Insert(aesUri, valuesBucket3);
    }
}

void MediaLibraryVisionTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("Vision_Test::Start");
    g_dataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    vector<string> perms;
    perms.push_back("ohos.permission.READ_MEDIA");
    perms.push_back("ohos.permission.WRITE_MEDIA");
    uint64_t tokenId = 0;
    PermissionUtilsUnitTest::SetAccessTokenPermission("MediaLibraryQueryPerfUnitTest", perms, tokenId);
    ASSERT_TRUE(tokenId != 0);
}

void MediaLibraryVisionTest::TearDownTestCase(void) {
    CleanVisionData();
    MEDIA_INFO_LOG("Vision_Test::End");
}

void MediaLibraryVisionTest::SetUp(void) {}

void MediaLibraryVisionTest::TearDown(void) {}

HWTEST_F(MediaLibraryVisionTest, Vision_InsertOcr_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_InsertOcr_Test_001::Start");
    Uri ocrUri(URI_OCR);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(OCR_TEXT, "inserttest");
    valuesBucket.Put(OCR_VERSION, "1.01");
    valuesBucket.Put(OCR_TEXT_MSG, "testmsg");
    auto retVal = g_dataShareHelper->Insert(ocrUri, valuesBucket);
    EXPECT_EQ((retVal > 0), true);
    MEDIA_INFO_LOG("Vision_InsertOcr_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryVisionTest, Vision_InsertOcr_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_InsertOcr_Test_002::Start");
    Uri ocrUri(URI_OCR);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 11111);
    valuesBucket.Put(OCR_TEXT, "inserttest");
    valuesBucket.Put(OCR_VERSION, "1.01");
    valuesBucket.Put(OCR_TEXT_MSG, "testmsg");
    auto retVal = g_dataShareHelper->Insert(ocrUri, valuesBucket);
    auto retVal2 = g_dataShareHelper->Insert(ocrUri, valuesBucket);
    EXPECT_EQ((retVal > 0 && retVal2 < 0), true);
    MEDIA_INFO_LOG("Vision_InsertOcr_Test_002::retVal = %{public}d. retVal2 = %{public}d. End", retVal, retVal2);
}

HWTEST_F(MediaLibraryVisionTest, Vision_UpdateOcr_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_UpdateOcr_Test_001::Start");
    Uri ocrUri(URI_OCR);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 11112);
    valuesBucket.Put(OCR_TEXT, "updatetest");
    valuesBucket.Put(OCR_VERSION, "1.01");
    valuesBucket.Put(OCR_TEXT_MSG, "testmsg");
    g_dataShareHelper->Insert(ocrUri, valuesBucket);
    DataShare::DataShareValuesBucket updateValues;
    updateValues.Put(OCR_TEXT, "updatetestend");
    updateValues.Put(OCR_VERSION, "2.01");
    DataShare::DataSharePredicates predicates;
    vector<string> inValues;
    inValues.push_back("11112");
    inValues.push_back("21233");
    predicates.In(FILE_ID, inValues);
    predicates.And();
    predicates.EqualTo(OCR_TEXT_MSG, "testmsg");
    auto retVal = g_dataShareHelper->Update(ocrUri, predicates, updateValues);
    vector<string> columns;
    columns.push_back(OCR_TEXT);
    columns.push_back(OCR_VERSION);
    auto resultSet = g_dataShareHelper->Query(ocrUri, predicates, columns);
    resultSet->GoToFirstRow();
    string ocrTest;
    string ocrVersion;
    resultSet->GetString(0, ocrTest);
    resultSet->GetString(1, ocrVersion);
    EXPECT_NE((resultSet == nullptr), true);
    EXPECT_EQ((retVal == 1), true);
    MEDIA_INFO_LOG("Vision_UpdateOcr_Test_001::ocrTest = %{public}s. End", ocrTest.c_str());
}

HWTEST_F(MediaLibraryVisionTest, Vision_DeleteOcr_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_DeleteOcr_Test_001::Start");
    Uri ocrUri(URI_OCR);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 11113);
    valuesBucket.Put(OCR_TEXT, "deletetest");
    valuesBucket.Put(OCR_VERSION, "1.01");
    valuesBucket.Put(OCR_TEXT_MSG, "testmsg");
    g_dataShareHelper->Insert(ocrUri, valuesBucket);
    DataShare::DataSharePredicates predicates;
    vector<string> inValues;
    inValues.push_back("11113");
    inValues.push_back("21233");
    predicates.In(FILE_ID, inValues);
    predicates.And();
    predicates.EqualTo(OCR_VERSION, "1.01");
    auto retVal = g_dataShareHelper->Delete(ocrUri, predicates);
    EXPECT_EQ((retVal == 1), true);
    MEDIA_INFO_LOG("Vision_DeleteOcr_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryVisionTest, Vision_InsertLabel_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_InsertLabel_Test_001::Start");
    Uri labelUri(URI_LABEL);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 1);
    valuesBucket.Put(CATEGORY_ID, 1);
    valuesBucket.Put(SUB_LABEL, 1);
    valuesBucket.Put(PROB, 2.344);
    valuesBucket.Put(LABEL_VERSION, 1);
    auto retVal = g_dataShareHelper->Insert(labelUri, valuesBucket);
    EXPECT_EQ((retVal > 0), true);
    MEDIA_INFO_LOG("Vision_InsertLabel_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryVisionTest, Vision_InsertLabel_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_InsertLabel_Test_002::Start");
    Uri labelUri(URI_LABEL);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 2);
    valuesBucket.Put(CATEGORY_ID, 1);
    valuesBucket.Put(SUB_LABEL, 1);
    valuesBucket.Put(PROB, 2.344);
    valuesBucket.Put(LABEL_VERSION, "1.01");
    auto retVal = g_dataShareHelper->Insert(labelUri, valuesBucket);
    DataShare::DataShareValuesBucket valuesBucket2;
    valuesBucket2.Put(FILE_ID, 2);
    valuesBucket2.Put(CATEGORY_ID, 1);
    valuesBucket2.Put(SUB_LABEL, 2);
    valuesBucket2.Put(PROB, 2.344);
    valuesBucket2.Put(LABEL_VERSION, "1.01");
    auto retVal2 = g_dataShareHelper->Insert(labelUri, valuesBucket2);
    EXPECT_EQ((retVal > 0 && retVal2 > 0), true);
    MEDIA_INFO_LOG("Vision_InsertLabel_Test_002::retVal = %{public}d. retVal2 = %{public}d. End", retVal, retVal2);
}

HWTEST_F(MediaLibraryVisionTest, Vision_UpdateLabel_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_UpdateLabel_Test_001::Start");
    Uri labelUri(URI_LABEL);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 3);
    valuesBucket.Put(CATEGORY_ID, 1);
    valuesBucket.Put(SUB_LABEL, 1);
    valuesBucket.Put(PROB, 2.344);
    valuesBucket.Put(LABEL_VERSION, "1.01");
    g_dataShareHelper->Insert(labelUri, valuesBucket);
    DataShare::DataShareValuesBucket updateValues;
    updateValues.Put(SUB_LABEL, 3);
    updateValues.Put(LABEL_VERSION, "2.01");
    DataShare::DataSharePredicates predicates;
    vector<string> inValues;
    inValues.push_back("123421");
    inValues.push_back("3");
    predicates.In(FILE_ID, inValues);
    auto retVal = g_dataShareHelper->Update(labelUri, predicates, updateValues);
    EXPECT_EQ((retVal == 1), true);
    MEDIA_INFO_LOG("Vision_UpdateLabel_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryVisionTest, Vision_DeleteLabel_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_DeleteLabel_Test_001::Start");
    Uri labelUri(URI_LABEL);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 4);
    valuesBucket.Put(CATEGORY_ID, 1);
    valuesBucket.Put(SUB_LABEL, 1);
    valuesBucket.Put(PROB, 2.344);
    valuesBucket.Put(LABEL_VERSION, "1.01");
    g_dataShareHelper->Insert(labelUri, valuesBucket);
    valuesBucket.Put(SUB_LABEL, 2);
    g_dataShareHelper->Insert(labelUri, valuesBucket);
    valuesBucket.Put(SUB_LABEL, 3);
    g_dataShareHelper->Insert(labelUri, valuesBucket);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(FILE_ID, 4);
    auto retVal = g_dataShareHelper->Delete(labelUri, predicates);
    EXPECT_EQ((retVal == 3), true);
    MEDIA_INFO_LOG("Vision_DeleteLabel_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryVisionTest, Vision_InsertAes_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_InsertAes_Test_001::Start");
    Uri aesUri(URI_AESTHETICS);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 1);
    valuesBucket.Put(AESTHETICS_SCORE, 1);
    valuesBucket.Put(AESTHETICS_VERSION, "1.01");
    valuesBucket.Put(PROB, 2.344);
    auto retVal = g_dataShareHelper->Insert(aesUri, valuesBucket);
    EXPECT_EQ((retVal > 0), true);
    MEDIA_INFO_LOG("Vision_InsertAes_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryVisionTest, Vision_InsertAes_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_InsertAes_Test_002::Start");
    Uri aesUri(URI_AESTHETICS);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 2);
    valuesBucket.Put(AESTHETICS_SCORE, 6);
    valuesBucket.Put(AESTHETICS_VERSION, "1.01");
    valuesBucket.Put(PROB, 2.344);
    auto retVal = g_dataShareHelper->Insert(aesUri, valuesBucket);
    DataShare::DataShareValuesBucket valuesBucket2;
    valuesBucket2.Put(FILE_ID, 2);
    valuesBucket.Put(AESTHETICS_SCORE, 6);
    valuesBucket.Put(AESTHETICS_VERSION, "1.01");
    valuesBucket.Put(PROB, 2.344);
    auto retVal2 = g_dataShareHelper->Insert(aesUri, valuesBucket2);
    EXPECT_EQ((retVal > 0 && retVal2 < 0), true);
    MEDIA_INFO_LOG("Vision_InsertAes_Test_002::retVal = %{public}d. retVal2 = %{public}d. End", retVal, retVal2);
}

HWTEST_F(MediaLibraryVisionTest, Vision_UpdateAes_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_UpdateAes_Test_001::Start");
    Uri aesUri(URI_AESTHETICS);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 3);
    valuesBucket.Put(AESTHETICS_SCORE, 6);
    valuesBucket.Put(AESTHETICS_VERSION, "1.01");
    valuesBucket.Put(PROB, 2.344);
    g_dataShareHelper->Insert(aesUri, valuesBucket);
    DataShare::DataShareValuesBucket updateValues;
    updateValues.Put(AESTHETICS_SCORE, 8);
    updateValues.Put(AESTHETICS_VERSION, "2.01");
    DataShare::DataSharePredicates predicates;
    vector<string> inValues;
    inValues.push_back("3");
    predicates.In(FILE_ID, inValues);
    auto retVal = g_dataShareHelper->Update(aesUri, predicates, updateValues);
    EXPECT_EQ((retVal == 1), true);
    MEDIA_INFO_LOG("Vision_UpdateAes_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryVisionTest, Vision_DeleteAes_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_DeleteAes_Test_001::Start");
    Uri aesUri(URI_AESTHETICS);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 4);
    valuesBucket.Put(AESTHETICS_SCORE, 6);
    valuesBucket.Put(AESTHETICS_VERSION, "1.01");
    valuesBucket.Put(PROB, 2.344);
    g_dataShareHelper->Insert(aesUri, valuesBucket);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(FILE_ID, 4);
    auto retVal = g_dataShareHelper->Delete(aesUri, predicates);
    EXPECT_EQ((retVal == 1), true);
    MEDIA_INFO_LOG("Vision_DeleteAes_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryVisionTest, Vision_Shield_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_Shield_Test_001::Start");
    Uri shieldUri(URI_SHIELD);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(SHIELD_KEY, "testkey1");
    valuesBucket.Put(SHIELD_VALUE, "testValue1");
    g_dataShareHelper->Insert(shieldUri, valuesBucket);
    valuesBucket.Put(SHIELD_KEY, "testkey2");
    valuesBucket.Put(SHIELD_VALUE, "testValue2");
    g_dataShareHelper->Insert(shieldUri, valuesBucket);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SHIELD_KEY, "testkey2");
    vector<string> columns;
    columns.push_back(SHIELD_KEY);
    columns.push_back(SHIELD_VALUE);
    auto resultSet = g_dataShareHelper->Query(shieldUri, predicates, columns);
    resultSet->GoToFirstRow();
    string key;
    string value;
    resultSet->GetString(0, key);
    resultSet->GetString(1, value);
    EXPECT_NE((resultSet == nullptr), true);
    MEDIA_INFO_LOG("Vision_Shield_Test_001::key = %{public}s, value = %{public}s End", key.c_str(), value.c_str());
}

HWTEST_F(MediaLibraryVisionTest, Vision_Performence_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_Performence_Test_001::Start");
    CleanVisionData();
    InitPerformanceData();
}
} // namespace Media
} // namespace OHOS
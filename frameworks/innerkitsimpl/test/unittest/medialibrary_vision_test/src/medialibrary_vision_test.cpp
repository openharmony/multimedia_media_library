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

#include "medialibrary_vision_test.h"
#include "datashare_result_set.h"
#include "get_self_permissions.h"
#include "media_log.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_unittest_utils.h"
#include "result_set_utils.h"
#include "uri.h"
#include "vision_column.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
void CleanVisionData()
{
    DataShare::DataSharePredicates predicates;
    Uri ocrUri(URI_OCR);
    MediaLibraryCommand ocrCmd(ocrUri);
    Uri labelUri(URI_LABEL);
    MediaLibraryCommand labelCmd(labelUri);
    Uri aesUri(URI_AESTHETICS);
    MediaLibraryCommand aesCmd(aesUri);
    Uri shieldUri(URI_SHIELD);
    MediaLibraryCommand shieldCmd(shieldUri);
    Uri totalUri(URI_TOTAL);
    MediaLibraryCommand totalCmd(totalUri);
    MediaLibraryDataManager::GetInstance()->Delete(ocrCmd, predicates);
    MediaLibraryDataManager::GetInstance()->Delete(labelCmd, predicates);
    MediaLibraryDataManager::GetInstance()->Delete(aesCmd, predicates);
    MediaLibraryDataManager::GetInstance()->Delete(shieldCmd, predicates);
    MediaLibraryDataManager::GetInstance()->Delete(totalCmd, predicates);
}

void MediaLibraryVisionTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("Vision_Test::Start");
    MediaLibraryUnitTestUtils::Init();
    vector<string> perms = { "ohos.permission.MEDIA_LOCATION" };
    uint64_t tokenId = 0;
    PermissionUtilsUnitTest::SetAccessTokenPermission("MediaLibraryQueryPerfUnitTest", perms, tokenId);
    ASSERT_TRUE(tokenId != 0);
}

void MediaLibraryVisionTest::TearDownTestCase(void)
{
    CleanVisionData();
    MEDIA_INFO_LOG("Vision_Test::End");
}

void MediaLibraryVisionTest::SetUp(void)
{
    MediaLibraryUnitTestUtils::CleanTestFiles();
    MediaLibraryUnitTestUtils::CleanBundlePermission();
    MediaLibraryUnitTestUtils::InitRootDirs();
    MediaLibraryUnitTestUtils::Init();
}

void MediaLibraryVisionTest::TearDown(void) {}

HWTEST_F(MediaLibraryVisionTest, Vision_InsertOcr_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_InsertOcr_Test_001::Start");
    Uri ocrUri(URI_OCR);
    MediaLibraryCommand cmd(ocrUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(OCR_TEXT, "inserttest");
    valuesBucket.Put(OCR_VERSION, "1.01");
    valuesBucket.Put(OCR_TEXT_MSG, "testmsg");
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    EXPECT_GT(retVal, 0);
    MEDIA_INFO_LOG("Vision_InsertOcr_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryVisionTest, Vision_InsertOcr_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_InsertOcr_Test_002::Start");
    Uri ocrUri(URI_OCR);
    MediaLibraryCommand cmd(ocrUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 11111);
    valuesBucket.Put(OCR_TEXT, "inserttest");
    valuesBucket.Put(OCR_VERSION, "1.01");
    valuesBucket.Put(OCR_TEXT_MSG, "testmsg");
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    auto retVal2 = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    EXPECT_GT(retVal, 0);
    EXPECT_LT(retVal2, 0);
    MEDIA_INFO_LOG("Vision_InsertOcr_Test_002::retVal = %{public}d. retVal2 = %{public}d. End", retVal, retVal2);
}

HWTEST_F(MediaLibraryVisionTest, Vision_UpdateOcr_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_UpdateOcr_Test_001::Start");
    Uri ocrUri(URI_OCR);
    MediaLibraryCommand cmd(ocrUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 11112);
    valuesBucket.Put(OCR_TEXT, "updatetest");
    valuesBucket.Put(OCR_VERSION, "1.01");
    valuesBucket.Put(OCR_TEXT_MSG, "testmsg");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
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
    auto retVal = MediaLibraryDataManager::GetInstance()->Update(cmd, updateValues, predicates);
    EXPECT_EQ((retVal == 1), true);
    vector<string> columns;
    columns.push_back(OCR_TEXT);
    columns.push_back(OCR_VERSION);
    int errCode = 0;
    auto queryResultSet = MediaLibraryDataManager::GetInstance()->Query(cmd, columns, predicates, errCode);
    shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>(queryResultSet);
    int count;
    resultSet->GetRowCount(count);
    EXPECT_GT(count, 0);
    resultSet->GoToFirstRow();
    string ocrTest;
    string ocrVersion;
    resultSet->GetString(0, ocrTest);
    resultSet->GetString(1, ocrVersion);
    MEDIA_INFO_LOG("Vision_UpdateOcr_Test_001::ocrTest = %{public}s ocr_version = %{public}s. End",
        ocrTest.c_str(), ocrVersion.c_str());
}

HWTEST_F(MediaLibraryVisionTest, Vision_DeleteOcr_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_DeleteOcr_Test_001::Start");
    Uri ocrUri(URI_OCR);
    MediaLibraryCommand cmd(ocrUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 11113);
    valuesBucket.Put(OCR_TEXT, "deletetest");
    valuesBucket.Put(OCR_VERSION, "1.01");
    valuesBucket.Put(OCR_TEXT_MSG, "testmsg");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    DataShare::DataSharePredicates predicates;
    vector<string> inValues;
    inValues.push_back("11113");
    inValues.push_back("21233");
    predicates.In(FILE_ID, inValues);
    predicates.And();
    predicates.EqualTo(OCR_VERSION, "1.01");
    auto retVal = MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates);
    EXPECT_EQ((retVal == 1), true);
    MEDIA_INFO_LOG("Vision_DeleteOcr_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryVisionTest, Vision_InsertLabel_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_InsertLabel_Test_001::Start");
    Uri labelUri(URI_LABEL);
    MediaLibraryCommand cmd(labelUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 1);
    valuesBucket.Put(CATEGORY_ID, 1);
    valuesBucket.Put(SUB_LABEL, "1,2,3");
    valuesBucket.Put(PROB, 2.344);
    valuesBucket.Put(FEATURE, "featuretest");
    valuesBucket.Put(SIM_RESULT, "sim_resulttest");
    valuesBucket.Put(LABEL_VERSION, 1);
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    EXPECT_GT(retVal, 0);
    MEDIA_INFO_LOG("Vision_InsertLabel_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryVisionTest, Vision_InsertLabel_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_InsertLabel_Test_002::Start");
    Uri labelUri(URI_LABEL);
    MediaLibraryCommand cmd(labelUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 2);
    valuesBucket.Put(CATEGORY_ID, 1);
    valuesBucket.Put(SUB_LABEL, "1,2,3");
    valuesBucket.Put(PROB, 2.344);
    valuesBucket.Put(FEATURE, "featuretest");
    valuesBucket.Put(SIM_RESULT, "sim_resulttest");
    valuesBucket.Put(LABEL_VERSION, "1.01");
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    DataShare::DataShareValuesBucket valuesBucket2;
    valuesBucket2.Put(FILE_ID, 2);
    valuesBucket2.Put(CATEGORY_ID, 1);
    valuesBucket2.Put(SUB_LABEL, "1,2,3");
    valuesBucket2.Put(PROB, 2.344);
    valuesBucket2.Put(FEATURE, "featuretest");
    valuesBucket2.Put(SIM_RESULT, "sim_resulttest");
    valuesBucket2.Put(LABEL_VERSION, "1.01");
    auto retVal2 = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket2);
    EXPECT_GT(retVal, 0);
    EXPECT_LT(retVal2, 0);
    MEDIA_INFO_LOG("Vision_InsertLabel_Test_002::retVal = %{public}d. retVal2 = %{public}d. End", retVal, retVal2);
}

HWTEST_F(MediaLibraryVisionTest, Vision_UpdateLabel_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_UpdateLabel_Test_001::Start");
    Uri labelUri(URI_LABEL);
    MediaLibraryCommand cmd(labelUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 3);
    valuesBucket.Put(CATEGORY_ID, 1);
    valuesBucket.Put(SUB_LABEL, 1);
    valuesBucket.Put(PROB, 2.344);
    valuesBucket.Put(FEATURE, "featuretest");
    valuesBucket.Put(SIM_RESULT, "sim_resulttest");
    valuesBucket.Put(LABEL_VERSION, "1.01");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    DataShare::DataShareValuesBucket updateValues;
    updateValues.Put(SUB_LABEL, 3);
    updateValues.Put(LABEL_VERSION, "2.01");
    DataShare::DataSharePredicates predicates;
    vector<string> inValues;
    inValues.push_back("123421");
    inValues.push_back("3");
    predicates.In(FILE_ID, inValues);
    auto retVal = MediaLibraryDataManager::GetInstance()->Update(cmd, updateValues, predicates);
    EXPECT_EQ((retVal == 1), true);
    MEDIA_INFO_LOG("Vision_UpdateLabel_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryVisionTest, Vision_DeleteLabel_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_DeleteLabel_Test_001::Start");
    Uri labelUri(URI_LABEL);
    MediaLibraryCommand cmd(labelUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 4);
    valuesBucket.Put(CATEGORY_ID, 1);
    valuesBucket.Put(SUB_LABEL, "1,2,3");
    valuesBucket.Put(PROB, 2.344);
    valuesBucket.Put(FEATURE, "featuretest");
    valuesBucket.Put(SIM_RESULT, "sim_resulttest");
    valuesBucket.Put(LABEL_VERSION, "1.01");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    DataShare::DataShareValuesBucket valuesBucket2;
    valuesBucket2.Put(FILE_ID, 5);
    valuesBucket2.Put(CATEGORY_ID, 1);
    valuesBucket2.Put(SUB_LABEL, "1,2,3");
    valuesBucket2.Put(PROB, 2.344);
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket2);
    DataShare::DataSharePredicates predicates;
    predicates.GreaterThan(FILE_ID, 3);
    auto retVal = MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates);
    EXPECT_EQ((retVal == 2), true);
    MEDIA_INFO_LOG("Vision_DeleteLabel_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryVisionTest, Vision_InsertAes_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_InsertAes_Test_001::Start");
    Uri aesUri(URI_AESTHETICS);
    MediaLibraryCommand cmd(aesUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 1);
    valuesBucket.Put(AESTHETICS_SCORE, 1);
    valuesBucket.Put(AESTHETICS_VERSION, "1.01");
    valuesBucket.Put(PROB, 2.344);
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    EXPECT_GT(retVal, 0);
    MEDIA_INFO_LOG("Vision_InsertAes_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryVisionTest, Vision_InsertAes_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_InsertAes_Test_002::Start");
    Uri aesUri(URI_AESTHETICS);
    MediaLibraryCommand cmd(aesUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 2);
    valuesBucket.Put(AESTHETICS_SCORE, 6);
    valuesBucket.Put(AESTHETICS_VERSION, "1.01");
    valuesBucket.Put(PROB, 2.344);
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    DataShare::DataShareValuesBucket valuesBucket2;
    valuesBucket2.Put(FILE_ID, 2);
    valuesBucket.Put(AESTHETICS_SCORE, 6);
    valuesBucket.Put(AESTHETICS_VERSION, "1.01");
    valuesBucket.Put(PROB, 2.344);
    auto retVal2 = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket2);
    EXPECT_GT(retVal, 0);
    EXPECT_LT(retVal2, 0);
    MEDIA_INFO_LOG("Vision_InsertAes_Test_002::retVal = %{public}d. retVal2 = %{public}d. End", retVal, retVal2);
}

HWTEST_F(MediaLibraryVisionTest, Vision_UpdateAes_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_UpdateAes_Test_001::Start");
    Uri aesUri(URI_AESTHETICS);
    MediaLibraryCommand cmd(aesUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 3);
    valuesBucket.Put(AESTHETICS_SCORE, 6);
    valuesBucket.Put(AESTHETICS_VERSION, "1.01");
    valuesBucket.Put(PROB, 2.344);
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    DataShare::DataShareValuesBucket updateValues;
    updateValues.Put(AESTHETICS_SCORE, 8);
    updateValues.Put(AESTHETICS_VERSION, "2.01");
    DataShare::DataSharePredicates predicates;
    vector<string> inValues;
    inValues.push_back("3");
    predicates.In(FILE_ID, inValues);
    auto retVal = MediaLibraryDataManager::GetInstance()->Update(cmd, updateValues, predicates);
    EXPECT_EQ((retVal == 1), true);
    MEDIA_INFO_LOG("Vision_UpdateAes_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryVisionTest, Vision_DeleteAes_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_DeleteAes_Test_001::Start");
    Uri aesUri(URI_AESTHETICS);
    MediaLibraryCommand cmd(aesUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 4);
    valuesBucket.Put(AESTHETICS_SCORE, 6);
    valuesBucket.Put(AESTHETICS_VERSION, "1.01");
    valuesBucket.Put(PROB, 2.344);
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(FILE_ID, 4);
    auto retVal = MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates);
    EXPECT_EQ((retVal == 1), true);
    MEDIA_INFO_LOG("Vision_DeleteAes_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryVisionTest, Vision_Shield_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_Shield_Test_001::Start");
    Uri shieldUri(URI_SHIELD);
    MediaLibraryCommand cmd(shieldUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(SHIELD_KEY, "testkey1");
    valuesBucket.Put(SHIELD_VALUE, "testValue1");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    DataShare::DataShareValuesBucket valuesBucket2;
    valuesBucket2.Put(SHIELD_KEY, "testkey2");
    valuesBucket2.Put(SHIELD_VALUE, "testValue2");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket2);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SHIELD_KEY, "testkey2");
    vector<string> columns;
    columns.push_back(SHIELD_KEY);
    columns.push_back(SHIELD_VALUE);
    int errCode = 0;
    auto queryResultSet = MediaLibraryDataManager::GetInstance()->Query(cmd, columns, predicates, errCode);
    shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>(queryResultSet);
    int count;
    resultSet->GetRowCount(count);
    EXPECT_GT(count, 0);
    resultSet->GoToFirstRow();
    string key;
    string value;
    resultSet->GetString(0, key);
    resultSet->GetString(1, value);
    MEDIA_INFO_LOG("Vision_Shield_Test_001::key = %{public}s, value = %{public}s End", key.c_str(), value.c_str());
}

HWTEST_F(MediaLibraryVisionTest, Vision_Total_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_Total_Test_001::Start");
    Uri totalUri(URI_TOTAL);
    MediaLibraryCommand cmd(totalUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 1);
    valuesBucket.Put(STATUS, 0);
    valuesBucket.Put(OCR, 1);
    valuesBucket.Put(LABEL, 0);
    valuesBucket.Put(AESTHETICS_SCORE, 0);
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    EXPECT_GT(retVal, 0);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(STATUS, 0);
    vector<string> columns;
    columns.push_back(STATUS);
    columns.push_back(OCR);
    int errCode = 0;
    auto queryResultSet = MediaLibraryDataManager::GetInstance()->Query(cmd, columns, predicates, errCode);
    shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>(queryResultSet);
    int count;
    resultSet->GetRowCount(count);
    EXPECT_GT(count, 0);
    resultSet->GoToFirstRow();
    int status;
    int ocr;
    resultSet->GetInt(0, status);
    resultSet->GetInt(1, ocr);
    MEDIA_INFO_LOG("Vision_Total_Test_001::key = %{public}d, value = %{public}d End", status, ocr);
}
} // namespace Media
} // namespace OHOS
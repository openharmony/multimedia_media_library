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
#include "location_column.h"
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
    Uri salUri(URI_SALIENCY);
    MediaLibraryCommand salCmd(salUri);
    Uri totalUri(URI_TOTAL);
    MediaLibraryCommand totalCmd(totalUri);
    MediaLibraryDataManager::GetInstance()->Delete(ocrCmd, predicates);
    MediaLibraryDataManager::GetInstance()->Delete(labelCmd, predicates);
    MediaLibraryDataManager::GetInstance()->Delete(aesCmd, predicates);
    MediaLibraryDataManager::GetInstance()->Delete(shieldCmd, predicates);
    MediaLibraryDataManager::GetInstance()->Delete(salCmd, predicates);
    MediaLibraryDataManager::GetInstance()->Delete(totalCmd, predicates);
}

int32_t GetAnalysisAlbumPredicates(const int32_t albumId, DataShare::DataSharePredicates &predicates)
{
    string onClause = "file_id = map_asset";
    predicates.InnerJoin(ANALYSIS_PHOTO_MAP_TABLE)->On({ onClause });
    predicates.EqualTo("map_album", to_string(albumId));
    predicates.EqualTo(MediaColumn::MEDIA_DATE_TRASHED, to_string(0));
    predicates.EqualTo(MediaColumn::MEDIA_HIDDEN, to_string(0));
    predicates.EqualTo(MediaColumn::MEDIA_TIME_PENDING, to_string(0));
    return 0;
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
    valuesBucket.Put(FILE_ID, 123);
    valuesBucket.Put(STATUS, 0);
    valuesBucket.Put(OCR, 1);
    valuesBucket.Put(LABEL, 0);
    valuesBucket.Put(AESTHETICS_SCORE, 0);
    valuesBucket.Put(FACE, 0);
    valuesBucket.Put(OBJECT, 0);
    valuesBucket.Put(RECOMMENDATION, 0);
    valuesBucket.Put(SEGMENTATION, 0);
    valuesBucket.Put(COMPOSITION, 0);
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

HWTEST_F(MediaLibraryVisionTest, Vision_InsertImageFace_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_InsertFaceImage_Test_001::Start");
    Uri imageFaceUri(URI_IMAGE_FACE);
    MediaLibraryCommand cmd(imageFaceUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 1);
    valuesBucket.Put(FACE_ID, 1);
    valuesBucket.Put(TAG_ID, "11");
    valuesBucket.Put(SCALE_X, 1.2);
    valuesBucket.Put(SCALE_Y, 1.3);
    valuesBucket.Put(SCALE_HEIGHT, 3.4);
    valuesBucket.Put(SCALE_WIDTH, 2.3);
    valuesBucket.Put(LANDMARKS, "{{222}}");
    valuesBucket.Put(PITCH, 4.5);
    valuesBucket.Put(YAW, 5.6);
    valuesBucket.Put(ROLL, 90);
    valuesBucket.Put(PROB, 0.9);
    valuesBucket.Put(TOTAL_FACES, 1);
    valuesBucket.Put(IMAGE_FACE_VERSION, "1.01");
    valuesBucket.Put(IMAGE_FEATURES_VERSION, "3.0");
    valuesBucket.Put(FEATURES, "xyijd");
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    EXPECT_GT(retVal, 0);
    MEDIA_INFO_LOG("Vision_InsertImageFace_Test_001::retVal = %{public}d. End", retVal);
    DataShare::DataShareValuesBucket valuesBucket1;
    valuesBucket1.Put(FILE_ID, 1);
    valuesBucket1.Put(FACE_ID, 1);
    valuesBucket1.Put(IMAGE_FACE_VERSION, "1.01");
    valuesBucket1.Put(PROB, 2.344);
    auto retVal1 = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket1);
    EXPECT_LT(retVal1, 0);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(FILE_ID, 1);
    MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates);
}

HWTEST_F(MediaLibraryVisionTest, Vision_UpdateImageFace_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_UpdateImageFace_Test_001::Start");
    Uri imageFaceUri(URI_IMAGE_FACE);
    MediaLibraryCommand cmd(imageFaceUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 2);
    valuesBucket.Put(FACE_ID, 3);
    valuesBucket.Put(TAG_ID, "22");
    valuesBucket.Put(SCALE_X, 2.2);
    valuesBucket.Put(SCALE_Y, 3.3);
    valuesBucket.Put(SCALE_HEIGHT, 5.4);
    valuesBucket.Put(SCALE_WIDTH, 6.3);
    valuesBucket.Put(LANDMARKS, "{{25522}}");
    valuesBucket.Put(PITCH, 6.5);
    valuesBucket.Put(YAW, 7.6);
    valuesBucket.Put(ROLL, 900);
    valuesBucket.Put(PROB, 0.1);
    valuesBucket.Put(TOTAL_FACES, 1);
    valuesBucket.Put(IMAGE_FACE_VERSION, "1.01");
    valuesBucket.Put(IMAGE_FEATURES_VERSION, "3.0");
    valuesBucket.Put(FEATURES, "vvvr");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    DataShare::DataShareValuesBucket updateValues;
    updateValues.Put(TOTAL_FACES, 8);
    updateValues.Put(IMAGE_FACE_VERSION, "2.01");
    DataShare::DataSharePredicates predicates;
    vector<string> inValues;
    inValues.push_back("2");
    predicates.In(FILE_ID, inValues);
    auto retVal = MediaLibraryDataManager::GetInstance()->Update(cmd, updateValues, predicates);
    EXPECT_EQ(retVal, 1);
    MEDIA_INFO_LOG("Vision_UpdateImageFace_Test_001::retVal = %{public}d. End", retVal);
    DataShare::DataSharePredicates predicates1;
    predicates1.EqualTo(FILE_ID, 2);
    MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates1);
}

HWTEST_F(MediaLibraryVisionTest, Vision_DeleteImageFace_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_DeleteImageFace_Test_001::Start");
    Uri imageFaceUri(URI_IMAGE_FACE);
    MediaLibraryCommand cmd(imageFaceUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 4);
    valuesBucket.Put(FACE_ID, 3);
    valuesBucket.Put(TAG_ID, "2442");
    valuesBucket.Put(SCALE_X, 3.2);
    valuesBucket.Put(SCALE_Y, 4.3);
    valuesBucket.Put(SCALE_HEIGHT, 4.4);
    valuesBucket.Put(SCALE_WIDTH, 4.3);
    valuesBucket.Put(LANDMARKS, "{{254522}}");
    valuesBucket.Put(PITCH, 64.54);
    valuesBucket.Put(YAW, 75.64);
    valuesBucket.Put(ROLL, 9004);
    valuesBucket.Put(PROB, 0.14);
    valuesBucket.Put(TOTAL_FACES, 1);
    valuesBucket.Put(IMAGE_FACE_VERSION, "1.041");
    valuesBucket.Put(IMAGE_FEATURES_VERSION, "34.0");
    valuesBucket.Put(FEATURES, "bb4");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);

    DataShare::DataShareValuesBucket valuesBucket1;
    valuesBucket1.Put(FILE_ID, 4);
    valuesBucket1.Put(FACE_ID, 2);
    valuesBucket1.Put(IMAGE_FACE_VERSION, "1.01");
    valuesBucket1.Put(PROB, 2.344);
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket1);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(FILE_ID, 4);
    auto retVal = MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates);
    EXPECT_EQ(retVal, 2);
    MEDIA_INFO_LOG("Vision_DeleteImageFace_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryVisionTest, Vision_QueryImageFace_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_QueryImageFace_Test_001::Start");
    Uri imageFaceUri(URI_IMAGE_FACE);
    MediaLibraryCommand cmd(imageFaceUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 5);
    valuesBucket.Put(FACE_ID, 3);
    valuesBucket.Put(TAG_ID, "24425");
    valuesBucket.Put(SCALE_X, 2.25);
    valuesBucket.Put(SCALE_Y, 3.36);
    valuesBucket.Put(SCALE_HEIGHT, 5.46);
    valuesBucket.Put(SCALE_WIDTH, 6.36);
    valuesBucket.Put(LANDMARKS, "{{255226}}");
    valuesBucket.Put(PITCH, 64.65);
    valuesBucket.Put(YAW, 75.66);
    valuesBucket.Put(ROLL, 9006);
    valuesBucket.Put(PROB, 0.16);
    valuesBucket.Put(TOTAL_FACES, 1);
    valuesBucket.Put(IMAGE_FACE_VERSION, "1.016");
    valuesBucket.Put(IMAGE_FEATURES_VERSION, "3.06");
    valuesBucket.Put(FEATURES, "bb66");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);

    DataShare::DataShareValuesBucket valuesBucket1;
    valuesBucket1.Put(FILE_ID, 5);
    valuesBucket1.Put(FACE_ID, 2);
    valuesBucket1.Put(IMAGE_FACE_VERSION, "1.015");
    valuesBucket1.Put(PROB, 2.344);
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket1);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(FILE_ID, 5);
    vector<string> columns;
    columns.push_back(FACE_ID);
    int errCode = 0;
    auto queryResultSet = MediaLibraryDataManager::GetInstance()->Query(cmd, columns, predicates, errCode);
    shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>(queryResultSet);
    int count;
    resultSet->GetRowCount(count);
    EXPECT_EQ(count, 2);
    DataShare::DataSharePredicates predicates1;
    predicates1.EqualTo(FILE_ID, 5);
    auto retVal = MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates1);
    EXPECT_EQ(retVal, 2);
}

HWTEST_F(MediaLibraryVisionTest, Vision_InsertFaceTag_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_InsertFaceTag_Test_001::Start");
    Uri faceTagUri(URI_FACE_TAG);
    MediaLibraryCommand cmd(faceTagUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(TAG_ID, "tag111");
    valuesBucket.Put(TAG_NAME, "me");
    valuesBucket.Put(USER_OPERATION, 1);
    valuesBucket.Put(GROUP_TAG, "tag111");
    valuesBucket.Put(RENAME_OPERATION, 1);
    valuesBucket.Put(CENTER_FEATURES, "dffd");
    valuesBucket.Put(TAG_VERSION, "2.2");
    valuesBucket.Put(USER_DISPLAY_LEVEL, 1);
    valuesBucket.Put(TAG_ORDER, 0);
    valuesBucket.Put(IS_ME, 1);
    valuesBucket.Put(COVER_URI, "xssdsf");
    valuesBucket.Put(COUNT, 1);
    valuesBucket.Put(DATE_MODIFY, 3333);
    valuesBucket.Put(ALBUM_TYPE, 1);
    valuesBucket.Put(IS_REMOVED, 1);
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    EXPECT_GT(retVal, 0);
    MEDIA_INFO_LOG("Vision_InsertImageFace_Test_001::retVal = %{public}d. End", retVal);
    DataShare::DataShareValuesBucket valuesBucket1;
    valuesBucket1.Put(TAG_ID, "tag111");
    valuesBucket1.Put(TAG_NAME, "me2");
    valuesBucket1.Put(IS_REMOVED, 1);
    valuesBucket1.Put(TAG_VERSION, "33");
    auto retVal1 = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket1);
    EXPECT_LT(retVal1, 0);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(TAG_ID, "tag111");
    MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates);
}

HWTEST_F(MediaLibraryVisionTest, Vision_UpdateFaceTag_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_UpdateFaceTag_Test_001::Start");
    Uri faceTagUri(URI_FACE_TAG);
    MediaLibraryCommand cmd(faceTagUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(TAG_ID, "tag333");
    valuesBucket.Put(TAG_NAME, "you");
    valuesBucket.Put(USER_OPERATION, 1);
    valuesBucket.Put(GROUP_TAG, "tag333");
    valuesBucket.Put(RENAME_OPERATION, 1);
    valuesBucket.Put(CENTER_FEATURES, "dffd2");
    valuesBucket.Put(TAG_VERSION, "2.22");
    valuesBucket.Put(USER_DISPLAY_LEVEL, 1);
    valuesBucket.Put(TAG_ORDER, 0);
    valuesBucket.Put(IS_ME, 1);
    valuesBucket.Put(COVER_URI, "xssdsf2");
    valuesBucket.Put(COUNT, 1);
    valuesBucket.Put(DATE_MODIFY, 2222);
    valuesBucket.Put(ALBUM_TYPE, 1);
    valuesBucket.Put(IS_REMOVED, 1);
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    DataShare::DataShareValuesBucket updateValues;
    updateValues.Put(TAG_NAME, "she");
    updateValues.Put(IS_REMOVED, 0);
    DataShare::DataSharePredicates predicates;
    vector<string> inValues;
    inValues.push_back("tag333");
    predicates.In(TAG_ID, inValues);
    auto retVal = MediaLibraryDataManager::GetInstance()->Update(cmd, updateValues, predicates);
    EXPECT_EQ(retVal, 1);
    MEDIA_INFO_LOG("Vision_UpdateFaceTag_Test_001::retVal = %{public}d. End", retVal);
    DataShare::DataSharePredicates predicates1;
    predicates1.EqualTo(TAG_ID, "tag333");
    MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates1);
}

HWTEST_F(MediaLibraryVisionTest, Vision_DeleteFaceTag_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_DeleteFaceTag_Test_001::Start");
    Uri faceTagUri(URI_FACE_TAG);
    MediaLibraryCommand cmd(faceTagUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(TAG_ID, "tag444");
    valuesBucket.Put(TAG_NAME, "he");
    valuesBucket.Put(USER_OPERATION, 1);
    valuesBucket.Put(GROUP_TAG, "tag444");
    valuesBucket.Put(RENAME_OPERATION, 1);
    valuesBucket.Put(CENTER_FEATURES, "dffd");
    valuesBucket.Put(TAG_VERSION, "2.24");
    valuesBucket.Put(USER_DISPLAY_LEVEL, 1);
    valuesBucket.Put(TAG_ORDER, 0);
    valuesBucket.Put(IS_ME, 1);
    valuesBucket.Put(COVER_URI, "xssdsf4");
    valuesBucket.Put(COUNT, 1);
    valuesBucket.Put(DATE_MODIFY, 444);
    valuesBucket.Put(ALBUM_TYPE, 1);
    valuesBucket.Put(IS_REMOVED, 1);
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);

    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(TAG_ID, "tag444");
    auto retVal = MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates);
    EXPECT_EQ(retVal, 1);
    MEDIA_INFO_LOG("Vision_DeleteFaceTag_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryVisionTest, Vision_QueryFaceTag_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_QueryFaceTag_Test_001::Start");
    Uri faceTagUri(URI_FACE_TAG);
    MediaLibraryCommand cmd(faceTagUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(TAG_ID, "tag555");
    valuesBucket.Put(TAG_NAME, "he");
    valuesBucket.Put(USER_OPERATION, 1);
    valuesBucket.Put(GROUP_TAG, "tag555");
    valuesBucket.Put(RENAME_OPERATION, 1);
    valuesBucket.Put(CENTER_FEATURES, "dffd");
    valuesBucket.Put(TAG_VERSION, "2.25");
    valuesBucket.Put(USER_DISPLAY_LEVEL, 1);
    valuesBucket.Put(TAG_ORDER, 0);
    valuesBucket.Put(IS_ME, 1);
    valuesBucket.Put(COVER_URI, "xssdsf5");
    valuesBucket.Put(COUNT, 1);
    valuesBucket.Put(DATE_MODIFY, 5555);
    valuesBucket.Put(ALBUM_TYPE, 1);
    valuesBucket.Put(IS_REMOVED, 1);
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);

    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(TAG_ID, "tag555");
    vector<string> columns;
    columns.push_back(TAG_NAME);
    int errCode = 0;
    auto queryResultSet = MediaLibraryDataManager::GetInstance()->Query(cmd, columns, predicates, errCode);
    shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>(queryResultSet);
    EXPECT_NE(resultSet, nullptr);
    int count;
    resultSet->GetRowCount(count);
    EXPECT_EQ(count, 1);
    DataShare::DataSharePredicates predicates1;
    predicates1.EqualTo(TAG_ID, "tag555");
    auto retVal = MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates1);
    EXPECT_EQ(retVal, 1);
}

HWTEST_F(MediaLibraryVisionTest, Vision_InsertObject_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_InsertObject_Test_001::Start");
    Uri objectUri(URI_OBJECT);
    MediaLibraryCommand cmd(objectUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 1);
    valuesBucket.Put(OBJECT_ID, 1);
    valuesBucket.Put(OBJECT_LABEL, 1);
    valuesBucket.Put(OBJECT_SCALE_X, 100);
    valuesBucket.Put(OBJECT_SCALE_Y, 200);
    valuesBucket.Put(OBJECT_SCALE_WIDTH, 500);
    valuesBucket.Put(OBJECT_SCALE_HEIGHT, 1000);
    valuesBucket.Put(OBJECT_VERSION, "1.0");
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    EXPECT_GT(retVal, 0);

    DataShare::DataShareValuesBucket valuesBucket1;
    valuesBucket1.Put(FILE_ID, 1);
    valuesBucket1.Put(OBJECT_ID, 1);
    valuesBucket1.Put(OBJECT_LABEL, 1);
    valuesBucket1.Put(OBJECT_SCALE_X, 500);
    valuesBucket1.Put(OBJECT_SCALE_Y, 600);
    valuesBucket1.Put(OBJECT_SCALE_WIDTH, 500);
    valuesBucket1.Put(OBJECT_SCALE_HEIGHT, 1000);
    valuesBucket1.Put(OBJECT_VERSION, "1.0");
    auto retVal1 = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket1);
    EXPECT_LT(retVal1, 0);
    MEDIA_INFO_LOG("Vision_InsertObject_Test_001::retVal = %{public}d. End", retVal);

    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(FILE_ID, 1);
    MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates);
}

HWTEST_F(MediaLibraryVisionTest, Vision_UpdateObject_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_UpdateObject_Test_001::Start");
    Uri objectUri(URI_OBJECT);
    MediaLibraryCommand cmd(objectUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 2);
    valuesBucket.Put(OBJECT_ID, 1);
    valuesBucket.Put(OBJECT_LABEL, 1);
    valuesBucket.Put(OBJECT_SCALE_X, 100);
    valuesBucket.Put(OBJECT_SCALE_Y, 200);
    valuesBucket.Put(OBJECT_SCALE_WIDTH, 500);
    valuesBucket.Put(OBJECT_SCALE_HEIGHT, 1000);
    valuesBucket.Put(OBJECT_VERSION, "1.0");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);

    DataShare::DataShareValuesBucket updateValues;
    updateValues.Put(OBJECT_SCALE_X, 200);
    updateValues.Put(OBJECT_SCALE_Y, 300);
    updateValues.Put(OBJECT_VERSION, "2.0");
    DataShare::DataSharePredicates predicates;
    vector<string> inValues;
    inValues.push_back("2");
    predicates.In(FILE_ID, inValues);
    auto retVal = MediaLibraryDataManager::GetInstance()->Update(cmd, updateValues, predicates);
    EXPECT_EQ(retVal, 1);
    MEDIA_INFO_LOG("Vision_UpdateObject_Test_001::retVal = %{public}d. End", retVal);

    DataShare::DataSharePredicates predicates1;
    predicates1.EqualTo(FILE_ID, 2);
    MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates1);
}

HWTEST_F(MediaLibraryVisionTest, Vision_DeleteObject_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_DeleteObject_Test_001::Start");
    Uri objectUri(URI_OBJECT);
    MediaLibraryCommand cmd(objectUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 3);
    valuesBucket.Put(OBJECT_ID, 1);
    valuesBucket.Put(OBJECT_LABEL, 1);
    valuesBucket.Put(OBJECT_SCALE_X, 100);
    valuesBucket.Put(OBJECT_SCALE_Y, 200);
    valuesBucket.Put(OBJECT_SCALE_WIDTH, 500);
    valuesBucket.Put(OBJECT_SCALE_HEIGHT, 1000);
    valuesBucket.Put(OBJECT_VERSION, "1.0");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);

    DataShare::DataShareValuesBucket valuesBucket1;
    valuesBucket1.Put(FILE_ID, 3);
    valuesBucket1.Put(OBJECT_ID, 2);
    valuesBucket1.Put(OBJECT_LABEL, 1);
    valuesBucket1.Put(OBJECT_SCALE_X, 500);
    valuesBucket1.Put(OBJECT_SCALE_Y, 600);
    valuesBucket1.Put(OBJECT_SCALE_WIDTH, 500);
    valuesBucket1.Put(OBJECT_SCALE_HEIGHT, 1000);
    valuesBucket1.Put(OBJECT_VERSION, "1.0");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket1);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(FILE_ID, 3);
    auto retVal = MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates);
    EXPECT_EQ(retVal, 2);
    MEDIA_INFO_LOG("Vision_DeleteObject_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryVisionTest, Vision_QueryObject_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_QueryObject_Test_001::Start");
    Uri objectUri(URI_OBJECT);
    MediaLibraryCommand cmd(objectUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 4);
    valuesBucket.Put(OBJECT_ID, 1);
    valuesBucket.Put(OBJECT_LABEL, 1);
    valuesBucket.Put(OBJECT_SCALE_X, 100);
    valuesBucket.Put(OBJECT_SCALE_Y, 200);
    valuesBucket.Put(OBJECT_SCALE_WIDTH, 500);
    valuesBucket.Put(OBJECT_SCALE_HEIGHT, 1000);
    valuesBucket.Put(OBJECT_VERSION, "1.0");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);

    DataShare::DataShareValuesBucket valuesBucket1;
    valuesBucket1.Put(FILE_ID, 4);
    valuesBucket1.Put(OBJECT_ID, 2);
    valuesBucket1.Put(OBJECT_LABEL, 1);
    valuesBucket1.Put(OBJECT_SCALE_X, 500);
    valuesBucket1.Put(OBJECT_SCALE_Y, 600);
    valuesBucket1.Put(OBJECT_SCALE_WIDTH, 500);
    valuesBucket1.Put(OBJECT_SCALE_HEIGHT, 1000);
    valuesBucket1.Put(OBJECT_VERSION, "1.0");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket1);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(FILE_ID, 4);
    vector<string> columns;
    columns.push_back(OBJECT_ID);
    int errCode = 0;
    auto queryResultSet = MediaLibraryDataManager::GetInstance()->Query(cmd, columns, predicates, errCode);
    shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>(queryResultSet);
    int count;
    resultSet->GetRowCount(count);
    EXPECT_EQ(count, 2);
    MEDIA_INFO_LOG("Vision_QueryObject_Test_001::retVal = %{public}d. End", count);

    DataShare::DataSharePredicates predicates1;
    predicates1.EqualTo(FILE_ID, 4);
    MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates1);
}

HWTEST_F(MediaLibraryVisionTest, Vision_InsertRecommendation_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_InsertRecommendation_Test_001::Start");
    Uri RecommendationUri(URI_RECOMMENDATION);
    MediaLibraryCommand cmd(RecommendationUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 1);
    valuesBucket.Put(RECOMMENDATION_ID, 1);
    valuesBucket.Put(RECOMMENDATION_RESOLUTION, "2000*1000");
    valuesBucket.Put(RECOMMENDATION_SCALE_X, 100);
    valuesBucket.Put(RECOMMENDATION_SCALE_Y, 200);
    valuesBucket.Put(RECOMMENDATION_SCALE_WIDTH, 500);
    valuesBucket.Put(RECOMMENDATION_SCALE_HEIGHT, 1000);
    valuesBucket.Put(RECOMMENDATION_VERSION, "1.0");
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    EXPECT_GT(retVal, 0);

    DataShare::DataShareValuesBucket valuesBucket1;
    valuesBucket1.Put(FILE_ID, 1);
    valuesBucket1.Put(RECOMMENDATION_ID, 1);
    valuesBucket1.Put(RECOMMENDATION_RESOLUTION, "2000*1000");
    valuesBucket1.Put(RECOMMENDATION_SCALE_X, 500);
    valuesBucket1.Put(RECOMMENDATION_SCALE_Y, 600);
    valuesBucket1.Put(RECOMMENDATION_SCALE_WIDTH, 500);
    valuesBucket1.Put(RECOMMENDATION_SCALE_HEIGHT, 1000);
    valuesBucket1.Put(RECOMMENDATION_VERSION, "1.0");
    auto retVal1 = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket1);
    EXPECT_LT(retVal1, 0);
    MEDIA_INFO_LOG("Vision_InsertRecommendation_Test_001::retVal = %{public}d. End", retVal);

    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(FILE_ID, 1);
    MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates);
}

HWTEST_F(MediaLibraryVisionTest, Vision_UpdateRecommendation_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_UpdateRecommendation_Test_001::Start");
    Uri RecommendationUri(URI_RECOMMENDATION);
    MediaLibraryCommand cmd(RecommendationUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 2);
    valuesBucket.Put(RECOMMENDATION_ID, 1);
    valuesBucket.Put(RECOMMENDATION_RESOLUTION, "2000*1000");
    valuesBucket.Put(RECOMMENDATION_SCALE_X, 100);
    valuesBucket.Put(RECOMMENDATION_SCALE_Y, 200);
    valuesBucket.Put(RECOMMENDATION_SCALE_WIDTH, 500);
    valuesBucket.Put(RECOMMENDATION_SCALE_HEIGHT, 1000);
    valuesBucket.Put(RECOMMENDATION_VERSION, "1.0");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);

    DataShare::DataShareValuesBucket updateValues;
    updateValues.Put(RECOMMENDATION_SCALE_X, 200);
    updateValues.Put(RECOMMENDATION_SCALE_Y, 300);
    updateValues.Put(RECOMMENDATION_VERSION, "2.0");
    DataShare::DataSharePredicates predicates;
    vector<string> inValues;
    inValues.push_back("2");
    predicates.In(FILE_ID, inValues);
    auto retVal = MediaLibraryDataManager::GetInstance()->Update(cmd, updateValues, predicates);
    EXPECT_EQ(retVal, 1);
    MEDIA_INFO_LOG("Vision_UpdateRecommendation_Test_001::retVal = %{public}d. End", retVal);

    DataShare::DataSharePredicates predicates1;
    predicates1.EqualTo(FILE_ID, 2);
    MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates1);
}

HWTEST_F(MediaLibraryVisionTest, Vision_DeleteRecommendation_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_DeleteRecommendation_Test_001::Start");
    Uri RecommendationUri(URI_RECOMMENDATION);
    MediaLibraryCommand cmd(RecommendationUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 3);
    valuesBucket.Put(RECOMMENDATION_ID, 1);
    valuesBucket.Put(RECOMMENDATION_RESOLUTION, "2000*1000");
    valuesBucket.Put(RECOMMENDATION_SCALE_X, 100);
    valuesBucket.Put(RECOMMENDATION_SCALE_Y, 200);
    valuesBucket.Put(RECOMMENDATION_SCALE_WIDTH, 500);
    valuesBucket.Put(RECOMMENDATION_SCALE_HEIGHT, 1000);
    valuesBucket.Put(RECOMMENDATION_VERSION, "1.0");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);

    DataShare::DataShareValuesBucket valuesBucket1;
    valuesBucket1.Put(FILE_ID, 3);
    valuesBucket1.Put(RECOMMENDATION_ID, 2);
    valuesBucket1.Put(RECOMMENDATION_RESOLUTION, "2000*1000");
    valuesBucket1.Put(RECOMMENDATION_SCALE_X, 500);
    valuesBucket1.Put(RECOMMENDATION_SCALE_Y, 600);
    valuesBucket1.Put(RECOMMENDATION_SCALE_WIDTH, 500);
    valuesBucket1.Put(RECOMMENDATION_SCALE_HEIGHT, 1000);
    valuesBucket1.Put(RECOMMENDATION_VERSION, "1.0");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket1);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(FILE_ID, 3);
    auto retVal = MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates);
    EXPECT_EQ(retVal, 2);
    MEDIA_INFO_LOG("Vision_DeleteRecommendation_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryVisionTest, Vision_QueryRecommendation_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_QueryRecommendation_Test_001::Start");
    Uri RecommendationUri(URI_RECOMMENDATION);
    MediaLibraryCommand cmd(RecommendationUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 4);
    valuesBucket.Put(RECOMMENDATION_ID, 1);
    valuesBucket.Put(RECOMMENDATION_RESOLUTION, "2000*1000");
    valuesBucket.Put(RECOMMENDATION_SCALE_X, 100);
    valuesBucket.Put(RECOMMENDATION_SCALE_Y, 200);
    valuesBucket.Put(RECOMMENDATION_SCALE_WIDTH, 500);
    valuesBucket.Put(RECOMMENDATION_SCALE_HEIGHT, 1000);
    valuesBucket.Put(RECOMMENDATION_VERSION, "1.0");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);

    DataShare::DataShareValuesBucket valuesBucket1;
    valuesBucket1.Put(FILE_ID, 4);
    valuesBucket1.Put(RECOMMENDATION_ID, 2);
    valuesBucket1.Put(RECOMMENDATION_RESOLUTION, "2000*1000");
    valuesBucket1.Put(RECOMMENDATION_SCALE_X, 500);
    valuesBucket1.Put(RECOMMENDATION_SCALE_Y, 600);
    valuesBucket1.Put(RECOMMENDATION_SCALE_WIDTH, 500);
    valuesBucket1.Put(RECOMMENDATION_SCALE_HEIGHT, 1000);
    valuesBucket1.Put(RECOMMENDATION_VERSION, "1.0");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket1);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(FILE_ID, 4);
    vector<string> columns;
    columns.push_back(RECOMMENDATION_ID);
    int errCode = 0;
    auto queryResultSet = MediaLibraryDataManager::GetInstance()->Query(cmd, columns, predicates, errCode);
    shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>(queryResultSet);
    int count;
    resultSet->GetRowCount(count);
    EXPECT_EQ(count, 2);
    MEDIA_INFO_LOG("Vision_QueryRecommendation_Test_001::retVal = %{public}d. End", count);

    DataShare::DataSharePredicates predicates1;
    predicates1.EqualTo(FILE_ID, 4);
    MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates1);
}

HWTEST_F(MediaLibraryVisionTest, Vision_InsertComposition_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_InsertComposition_Test_001::Start");
    Uri CompositionUri(URI_COMPOSITION);
    MediaLibraryCommand cmd(CompositionUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 1);
    valuesBucket.Put(COMPOSITION_ID, 1);
    valuesBucket.Put(COMPOSITION_RESOLUTION, "2000*1000");
    valuesBucket.Put(CLOCK_STYLE, 0);
    valuesBucket.Put(CLOCK_LOCATION_X, 700);
    valuesBucket.Put(CLOCK_LOCATION_Y, 800);
    valuesBucket.Put(CLOCK_COLOUR, "122*90*60");
    valuesBucket.Put(COMPOSITION_SCALE_X, 100);
    valuesBucket.Put(COMPOSITION_SCALE_Y, 200);
    valuesBucket.Put(COMPOSITION_SCALE_WIDTH, 500);
    valuesBucket.Put(COMPOSITION_SCALE_HEIGHT, 1000);
    valuesBucket.Put(COMPOSITION_VERSION, "1.0");
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    EXPECT_GT(retVal, 0);

    DataShare::DataShareValuesBucket valuesBucket1;
    valuesBucket1.Put(FILE_ID, 1);
    valuesBucket1.Put(COMPOSITION_ID, 1);
    valuesBucket1.Put(COMPOSITION_RESOLUTION, "2100*1100");
    valuesBucket1.Put(CLOCK_STYLE, 0);
    valuesBucket1.Put(CLOCK_LOCATION_X, 1000);
    valuesBucket1.Put(CLOCK_LOCATION_Y, 1100);
    valuesBucket1.Put(CLOCK_COLOUR, "30*140*80");
    valuesBucket1.Put(COMPOSITION_SCALE_X, 500);
    valuesBucket1.Put(COMPOSITION_SCALE_Y, 600);
    valuesBucket1.Put(COMPOSITION_SCALE_WIDTH, 550);
    valuesBucket1.Put(COMPOSITION_SCALE_HEIGHT, 1150);
    valuesBucket1.Put(COMPOSITION_VERSION, "1.0");
    auto retVal1 = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket1);
    EXPECT_LT(retVal1, 0);
    MEDIA_INFO_LOG("Vision_InsertComposition_Test_001::retVal = %{public}d. End", retVal);

    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(FILE_ID, 1);
    MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates);
}

HWTEST_F(MediaLibraryVisionTest, Vision_UpdateComposition_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_UpdateComposition_Test_001::Start");
    Uri CompositionUri(URI_COMPOSITION);
    MediaLibraryCommand cmd(CompositionUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 2);
    valuesBucket.Put(COMPOSITION_ID, 1);
    valuesBucket.Put(COMPOSITION_RESOLUTION, "2000*1000");
    valuesBucket.Put(CLOCK_STYLE, 0);
    valuesBucket.Put(CLOCK_LOCATION_X, 700);
    valuesBucket.Put(CLOCK_LOCATION_Y, 800);
    valuesBucket.Put(CLOCK_COLOUR, "122*90*60");
    valuesBucket.Put(COMPOSITION_SCALE_X, 100);
    valuesBucket.Put(COMPOSITION_SCALE_Y, 200);
    valuesBucket.Put(COMPOSITION_SCALE_WIDTH, 500);
    valuesBucket.Put(COMPOSITION_SCALE_HEIGHT, 1000);
    valuesBucket.Put(COMPOSITION_VERSION, "1.0");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);

    DataShare::DataShareValuesBucket updateValues;
    updateValues.Put(COMPOSITION_SCALE_X, 200);
    updateValues.Put(COMPOSITION_SCALE_Y, 300);
    updateValues.Put(COMPOSITION_VERSION, "2.0");
    DataShare::DataSharePredicates predicates;
    vector<string> inValues;
    inValues.push_back("2");
    predicates.In(FILE_ID, inValues);
    auto retVal = MediaLibraryDataManager::GetInstance()->Update(cmd, updateValues, predicates);
    EXPECT_EQ(retVal, 1);
    MEDIA_INFO_LOG("Vision_UpdateComposition_Test_001::retVal = %{public}d. End", retVal);

    DataShare::DataSharePredicates predicates1;
    predicates1.EqualTo(FILE_ID, 2);
    MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates1);
}

HWTEST_F(MediaLibraryVisionTest, Vision_DeleteComposition_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_DeleteComposition_Test_001::Start");
    Uri CompositionUri(URI_COMPOSITION);
    MediaLibraryCommand cmd(CompositionUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 3);
    valuesBucket.Put(COMPOSITION_ID, 1);
    valuesBucket.Put(COMPOSITION_RESOLUTION, "2000*1000");
    valuesBucket.Put(CLOCK_STYLE, 0);
    valuesBucket.Put(CLOCK_LOCATION_X, 700);
    valuesBucket.Put(CLOCK_LOCATION_Y, 800);
    valuesBucket.Put(CLOCK_COLOUR, "122*90*60");
    valuesBucket.Put(COMPOSITION_SCALE_X, 100);
    valuesBucket.Put(COMPOSITION_SCALE_Y, 200);
    valuesBucket.Put(COMPOSITION_SCALE_WIDTH, 500);
    valuesBucket.Put(COMPOSITION_SCALE_HEIGHT, 1000);
    valuesBucket.Put(COMPOSITION_VERSION, "1.0");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);

    DataShare::DataShareValuesBucket valuesBucket1;
    valuesBucket1.Put(FILE_ID, 3);
    valuesBucket1.Put(COMPOSITION_ID, 2);
    valuesBucket1.Put(COMPOSITION_RESOLUTION, "2100*1100");
    valuesBucket1.Put(CLOCK_STYLE, 0);
    valuesBucket1.Put(CLOCK_LOCATION_X, 1000);
    valuesBucket1.Put(CLOCK_LOCATION_Y, 1100);
    valuesBucket1.Put(CLOCK_COLOUR, "30*140*80");
    valuesBucket1.Put(COMPOSITION_SCALE_X, 500);
    valuesBucket1.Put(COMPOSITION_SCALE_Y, 600);
    valuesBucket1.Put(COMPOSITION_SCALE_WIDTH, 550);
    valuesBucket1.Put(COMPOSITION_SCALE_HEIGHT, 1150);
    valuesBucket1.Put(COMPOSITION_VERSION, "1.0");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket1);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(FILE_ID, 3);
    auto retVal = MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates);
    EXPECT_EQ(retVal, 2);
    MEDIA_INFO_LOG("Vision_DeleteComposition_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryVisionTest, Vision_QueryComposition_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_QueryComposition_Test_001::Start");
    Uri CompositionUri(URI_COMPOSITION);
    MediaLibraryCommand cmd(CompositionUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 4);
    valuesBucket.Put(COMPOSITION_ID, 1);
    valuesBucket.Put(COMPOSITION_RESOLUTION, "2000*1000");
    valuesBucket.Put(CLOCK_STYLE, 0);
    valuesBucket.Put(CLOCK_LOCATION_X, 700);
    valuesBucket.Put(CLOCK_LOCATION_Y, 800);
    valuesBucket.Put(CLOCK_COLOUR, "122*90*60");
    valuesBucket.Put(COMPOSITION_SCALE_X, 100);
    valuesBucket.Put(COMPOSITION_SCALE_Y, 200);
    valuesBucket.Put(COMPOSITION_SCALE_WIDTH, 500);
    valuesBucket.Put(COMPOSITION_SCALE_HEIGHT, 1000);
    valuesBucket.Put(COMPOSITION_VERSION, "1.0");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);

    DataShare::DataShareValuesBucket valuesBucket1;
    valuesBucket1.Put(FILE_ID, 4);
    valuesBucket1.Put(COMPOSITION_ID, 2);
    valuesBucket1.Put(COMPOSITION_RESOLUTION, "2100*1100");
    valuesBucket1.Put(CLOCK_STYLE, 0);
    valuesBucket1.Put(CLOCK_LOCATION_X, 1000);
    valuesBucket1.Put(CLOCK_LOCATION_Y, 1100);
    valuesBucket1.Put(CLOCK_COLOUR, "30*140*80");
    valuesBucket1.Put(COMPOSITION_SCALE_X, 500);
    valuesBucket1.Put(COMPOSITION_SCALE_Y, 600);
    valuesBucket1.Put(COMPOSITION_SCALE_WIDTH, 550);
    valuesBucket1.Put(COMPOSITION_SCALE_HEIGHT, 1150);
    valuesBucket1.Put(COMPOSITION_VERSION, "1.0");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket1);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(FILE_ID, 4);
    vector<string> columns;
    columns.push_back(COMPOSITION_ID);
    int errCode = 0;
    auto queryResultSet = MediaLibraryDataManager::GetInstance()->Query(cmd, columns, predicates, errCode);
    shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>(queryResultSet);
    int count;
    resultSet->GetRowCount(count);
    EXPECT_EQ(count, 2);
    MEDIA_INFO_LOG("Vision_QueryComposition_Test_001::retVal = %{public}d. End", count);

    DataShare::DataSharePredicates predicates1;
    predicates1.EqualTo(FILE_ID, 4);
    MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates1);
}

HWTEST_F(MediaLibraryVisionTest, Vision_InsertSegmentation_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_InsertSegmentation_Test_001::Start");
    Uri SegmentationUri(URI_SEGMENTATION);
    MediaLibraryCommand cmd(SegmentationUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 1);
    valuesBucket.Put(SEGMENTATION_AREA, "1,2,3,4,5,6,7,8,9,10");
    valuesBucket.Put(SEGMENTATION_VERSION, "1.0");
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    EXPECT_GT(retVal, 0);

    DataShare::DataShareValuesBucket valuesBucket1;
    valuesBucket1.Put(FILE_ID, 1);
    valuesBucket1.Put(SEGMENTATION_AREA, "11,12,13,14,15,16,17,18,19,20");
    valuesBucket1.Put(SEGMENTATION_VERSION, "1.0");
    auto retVal1 = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket1);
    EXPECT_LT(retVal1, 0);
    MEDIA_INFO_LOG("Vision_InsertSegmentation_Test_001::retVal = %{public}d. End", retVal);

    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(FILE_ID, 1);
    MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates);
}

HWTEST_F(MediaLibraryVisionTest, Vision_UpdateSegmentation_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_UpdateSegmentation_Test_001::Start");
    Uri SegmentationUri(URI_SEGMENTATION);
    MediaLibraryCommand cmd(SegmentationUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 2);
    valuesBucket.Put(SEGMENTATION_AREA, "1,2,3,4,5,6,7,8,9,10");
    valuesBucket.Put(SEGMENTATION_VERSION, "1.0");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);

    DataShare::DataShareValuesBucket updateValues;
    updateValues.Put(SEGMENTATION_AREA, "11,12,13,14,15,16,17,18,19,20");
    updateValues.Put(SEGMENTATION_VERSION, "2.0");
    DataShare::DataSharePredicates predicates;
    vector<string> inValues;
    inValues.push_back("2");
    predicates.In(FILE_ID, inValues);
    auto retVal = MediaLibraryDataManager::GetInstance()->Update(cmd, updateValues, predicates);
    EXPECT_EQ(retVal, 1);
    MEDIA_INFO_LOG("Vision_UpdateSegmentation_Test_001::retVal = %{public}d. End", retVal);

    DataShare::DataSharePredicates predicates1;
    predicates1.EqualTo(FILE_ID, 2);
    MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates1);
}

HWTEST_F(MediaLibraryVisionTest, Vision_DeleteSegmentation_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_DeleteSegmentation_Test_001::Start");
    Uri SegmentationUri(URI_SEGMENTATION);
    MediaLibraryCommand cmd(SegmentationUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 3);
    valuesBucket.Put(SEGMENTATION_AREA, "1,2,3,4,5,6,7,8,9,10");
    valuesBucket.Put(SEGMENTATION_VERSION, "1.0");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);

    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(FILE_ID, 3);
    auto retVal = MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates);
    EXPECT_EQ(retVal, 1);
    MEDIA_INFO_LOG("Vision_DeleteSegmentation_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryVisionTest, Vision_QuerySegmentation_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_QuerySegmentation_Test_001::Start");
    Uri SegmentationUri(URI_SEGMENTATION);
    MediaLibraryCommand cmd(SegmentationUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 4);
    valuesBucket.Put(SEGMENTATION_AREA, "1,2,3,4,5,6,7,8,9,10");
    valuesBucket.Put(SEGMENTATION_VERSION, "1.0");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);

    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(FILE_ID, 4);
    vector<string> columns;
    columns.push_back(SEGMENTATION_AREA);
    columns.push_back(SEGMENTATION_VERSION);
    int errCode = 0;
    auto queryResultSet = MediaLibraryDataManager::GetInstance()->Query(cmd, columns, predicates, errCode);
    shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>(queryResultSet);
    int count;
    resultSet->GetRowCount(count);
    EXPECT_GT(count, 0);
    MEDIA_INFO_LOG("Vision_QuerySegmentation_Test_001::retVal = %{public}d. End", count);

    DataShare::DataSharePredicates predicates1;
    predicates1.EqualTo(FILE_ID, 4);
    MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates1);
}

HWTEST_F(MediaLibraryVisionTest, Vision_InsertSal_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_InsertSal_Test_001::Start");
    Uri salUri(URI_SALIENCY);
    MediaLibraryCommand cmd(salUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 1);
    valuesBucket.Put(SALIENCY_X, 0.5);
    valuesBucket.Put(SALIENCY_Y, 0.5);
    valuesBucket.Put(SALIENCY_VERSION, "1");
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    EXPECT_GT(retVal, 0);
    MEDIA_INFO_LOG("Vision_InsertSal_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryVisionTest, Vision_InsertSal_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_InsertSal_Test_002::Start");
    Uri salUri(URI_SALIENCY);
    MediaLibraryCommand cmd(salUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 2);
    valuesBucket.Put(SALIENCY_X, 0.5);
    valuesBucket.Put(SALIENCY_Y, 0.5);
    valuesBucket.Put(SALIENCY_VERSION, "1.01");
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    DataShare::DataShareValuesBucket valuesBucket2;
    valuesBucket2.Put(FILE_ID, 2);
    valuesBucket2.Put(SALIENCY_X, 0.5);
    valuesBucket2.Put(SALIENCY_Y, 0.5);
    valuesBucket2.Put(SALIENCY_VERSION, "1.01");
    auto retVal2 = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket2);
    EXPECT_GT(retVal, 0);
    EXPECT_LT(retVal2, 0);
    MEDIA_INFO_LOG("Vision_InsertSal_Test_002::retVal = %{public}d. retVal2 = %{public}d. End", retVal, retVal2);
}

HWTEST_F(MediaLibraryVisionTest, Vision_UpdateSal_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_UpdateSal_Test_001::Start");
    Uri salUri(URI_SALIENCY);
    MediaLibraryCommand cmd(salUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 3);
    valuesBucket.Put(SALIENCY_X, 0.5);
    valuesBucket.Put(SALIENCY_Y, 0.5);
    valuesBucket.Put(SALIENCY_VERSION, "1.01");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    DataShare::DataShareValuesBucket updateValues;
    updateValues.Put(SALIENCY_X, 0.1);
    updateValues.Put(SALIENCY_VERSION, "2.01");
    DataShare::DataSharePredicates predicates;
    vector<string> inValues;
    inValues.push_back("123421");
    inValues.push_back("3");
    predicates.In(FILE_ID, inValues);
    auto retVal = MediaLibraryDataManager::GetInstance()->Update(cmd, updateValues, predicates);
    EXPECT_EQ((retVal == 1), true);
    MEDIA_INFO_LOG("Vision_UpdateSal_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryVisionTest, Vision_DeleteSal_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_DeleteSal_Test_001::Start");
    Uri salUri(URI_SALIENCY);
    MediaLibraryCommand cmd(salUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(FILE_ID, 4);
    valuesBucket.Put(SALIENCY_X, 0.5);
    valuesBucket.Put(SALIENCY_Y, 0.5);
    valuesBucket.Put(SALIENCY_VERSION, "1.01");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    DataShare::DataShareValuesBucket valuesBucket2;
    valuesBucket2.Put(FILE_ID, 5);
    valuesBucket2.Put(SALIENCY_X, 0.1);
    valuesBucket2.Put(SALIENCY_Y, 0.2);
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket2);
    DataShare::DataSharePredicates predicates;
    predicates.GreaterThan(FILE_ID, 3);
    auto retVal = MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates);
    EXPECT_EQ((retVal == 2), true);
    MEDIA_INFO_LOG("Vision_DeleteSal_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryVisionTest, Vision_AnalysisAlbum_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_AnalysisAlbum_Test_001::Start");
    Uri analysisAlbumUri(PAH_INSERT_ANA_PHOTO_ALBUM);
    MediaLibraryCommand cmd(analysisAlbumUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(ALBUM_TYPE, PhotoAlbumType::SMART);
    valuesBucket.Put(ALBUM_SUBTYPE, PhotoAlbumSubType::CLASSIFY_CATEGORY);
    valuesBucket.Put(ALBUM_NAME, "1");
    valuesBucket.Put(DATE_MODIFIED, 0);
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    EXPECT_GT(retVal, 0);

    Uri queryAlbumUri(PAH_QUERY_ANA_PHOTO_ALBUM);
    MediaLibraryCommand queryCmd(queryAlbumUri);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(ALBUM_NAME, "1");
    vector<string> columns;
    int errCode = 0;
    auto queryResultSet = MediaLibraryDataManager::GetInstance()->Query(queryCmd, columns, predicates, errCode);
    shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>(queryResultSet);
    int count;
    resultSet->GetRowCount(count);
    EXPECT_GT(count, 0);
    MEDIA_INFO_LOG("Vision_AnalysisAlbum_Test_001::count = %{public}d. End", count);
}

HWTEST_F(MediaLibraryVisionTest, Vision_AnalysisAlbum_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_AnalysisAlbum_Test_002::Start");
    Uri analysisAlbumUri(PAH_INSERT_ANA_PHOTO_ALBUM);
    MediaLibraryCommand cmd(analysisAlbumUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(ALBUM_TYPE, PhotoAlbumType::SMART);
    valuesBucket.Put(ALBUM_SUBTYPE, PhotoAlbumSubType::CLASSIFY_CATEGORY);
    valuesBucket.Put(ALBUM_NAME, "2");
    valuesBucket.Put(COUNT, 1);
    valuesBucket.Put(DATE_MODIFIED, 0);
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    EXPECT_GT(retVal, 0);

    Uri updateAlbumUri(PAH_UPDATE_ANA_PHOTO_ALBUM);
    MediaLibraryCommand updateCmd(updateAlbumUri);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(ALBUM_NAME, "2");
    DataShare::DataShareValuesBucket updateValues;
    updateValues.Put(COUNT, 2);
    vector<string> columns;
    auto retVal2 = MediaLibraryDataManager::GetInstance()->Update(updateCmd, updateValues, predicates);
    EXPECT_GT(retVal2, 0);
    MEDIA_INFO_LOG("Vision_AnalysisAlbum_Test_002::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryVisionTest, Vision_AnalysisAlbum_Test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_AnalysisAlbum_Test_003::Start");
    Uri analysisAlbumUri(PAH_INSERT_ANA_PHOTO_ALBUM);
    MediaLibraryCommand cmd(analysisAlbumUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(ALBUM_TYPE, PhotoAlbumType::SMART);
    valuesBucket.Put(ALBUM_SUBTYPE, PhotoAlbumSubType::GEOGRAPHY_CITY);
    valuesBucket.Put(ALBUM_NAME, "shanghai");
    valuesBucket.Put(DATE_MODIFIED, 0);
    valuesBucket.Put(COUNT, 1);
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    EXPECT_GT(retVal, 0);

    
    Uri geoKnowDictionaryUri(URI_GEO_DICTIONARY);
    MediaLibraryCommand insertcmd(geoKnowDictionaryUri);
    DataShare::DataShareValuesBucket valuesBucket1;
    valuesBucket1.Put(CITY_ID, "shanghai");
    valuesBucket1.Put(LANGUAGE, "en");
    valuesBucket1.Put(CITY_NAME, "shanghai");
    auto retVal1 = MediaLibraryDataManager::GetInstance()->Insert(insertcmd, valuesBucket1);
    EXPECT_GT(retVal1, 0);


    Uri queryAlbumUri(PAH_QUERY_ANA_PHOTO_ALBUM);
    MediaLibraryCommand queryCmd(queryAlbumUri);
    DataShare::DataSharePredicates predicates;

    string onClause = "album_name = city_id";
    predicates.And()->InnerJoin(GEO_DICTIONARY_TABLE)->On({ onClause });
    predicates.EqualTo(ALBUM_NAME, "shanghai");
    predicates.And()->EqualTo(LANGUAGE, "en");
    vector<string> columns;
    int errCode = 0;
    auto queryResultSet = MediaLibraryDataManager::GetInstance()->Query(queryCmd, columns, predicates, errCode);
    shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>(queryResultSet);
    int count;
    resultSet->GetRowCount(count);
    EXPECT_GT(count, 0);

    MEDIA_INFO_LOG("Vision_AnalysisAlbum_Test_003::count = %{public}d. End", count);
}

HWTEST_F(MediaLibraryVisionTest, Vision_AnalysisAlbumMap_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Vision_AnalysisAlbumMap_Test_001::Start");
    Uri analysisAlbumUri(PAH_INSERT_ANA_PHOTO_ALBUM);
    MediaLibraryCommand cmd(analysisAlbumUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(ALBUM_TYPE, PhotoAlbumType::SMART);
    valuesBucket.Put(ALBUM_SUBTYPE, PhotoAlbumSubType::CLASSIFY_CATEGORY);
    valuesBucket.Put(ALBUM_NAME, "3");
    valuesBucket.Put(COUNT, 1);
    valuesBucket.Put(DATE_MODIFIED, 0);
    int albumId = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);

    Uri insertMapUri(PAH_INSERT_ANA_PHOTO_MAP);
    MediaLibraryCommand insertMapCmd(insertMapUri);
    DataShare::DataShareValuesBucket mapValues;
    mapValues.Put(MAP_ALBUM, albumId);
    mapValues.Put(MAP_ASSET, 1);
    int mapId = MediaLibraryDataManager::GetInstance()->Insert(insertMapCmd, mapValues);
    EXPECT_GT(mapId, 0);
    MEDIA_INFO_LOG("Vision_AnalysisAlbumMap_Test_001::mapId = %{public}d. End", mapId);
}
} // namespace Media
} // namespace OHOS
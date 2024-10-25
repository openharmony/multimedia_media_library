/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#define MLOG_TAG "MediaLibraryLocationTest"

#include "medialibrary_location_test.h"

#include "datashare_result_set.h"
#include "get_self_permissions.h"
#include "location_column.h"
#include "media_log.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_errno.h"
#include "medialibrary_unittest_utils.h"
#include "result_set_utils.h"
#include "uri.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
void ClearLocationData()
{
    DataShare::DataSharePredicates predicates;
    Uri geoKnowledgeUri(URI_GEO_KEOWLEDGE);
    MediaLibraryCommand geoKnowledgeCmd(geoKnowledgeUri);
    Uri geoDictionaryUri(URI_GEO_DICTIONARY);
    MediaLibraryCommand geoDictionaryCmd(geoDictionaryUri);
    MediaLibraryDataManager::GetInstance()->Delete(geoKnowledgeCmd, predicates);
    MediaLibraryDataManager::GetInstance()->Delete(geoDictionaryCmd, predicates);
}

void MediaLibraryLocationTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("Location_Test::Start");
    MediaLibraryUnitTestUtils::Init();
}

void MediaLibraryLocationTest::TearDownTestCase(void)
{
    ClearLocationData();
    MEDIA_INFO_LOG("Location_Test::End");
}

void MediaLibraryLocationTest::SetUp(void)
{
    MediaLibraryUnitTestUtils::CleanTestFiles();
    MediaLibraryUnitTestUtils::CleanBundlePermission();
    MediaLibraryUnitTestUtils::InitRootDirs();
    MediaLibraryUnitTestUtils::Init();
    ClearLocationData();
}

void MediaLibraryLocationTest::TearDown(void) {}

HWTEST_F(MediaLibraryLocationTest, Location_InsertGeoKnowledge_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Location_InsertGeoKnowledge_Test_001::Start");
    Uri geoKnowledgeUri(URI_GEO_KEOWLEDGE);
    MediaLibraryCommand cmd(geoKnowledgeUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(LATITUDE, 31.3107738494873);
    valuesBucket.Put(LONGITUDE, 120.6175308227539);
    valuesBucket.Put(LOCATION_KEY, 141189990037);
    valuesBucket.Put(LANGUAGE, "zh");
    valuesBucket.Put(COUNTRY, "中国");
    valuesBucket.Put(CITY_ID, "123456789101232");
    valuesBucket.Put(ADMIN_AREA, "江苏省");
    valuesBucket.Put(LOCALITY, "苏州市");
    valuesBucket.Put(SUB_LOCALITY, "姑苏区");
    valuesBucket.Put(THOROUGHFARE, "人民路");
    valuesBucket.Put(SUB_THOROUGHFARE, "1285号");
    valuesBucket.Put(CITY_NAME, "苏州市");
    valuesBucket.Put(ADDRESS_DESCRIPTION, "中国江苏省苏州市姑苏区人民路辅路苏州国美电器人名路旗舰店");
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    EXPECT_GT(retVal, 0);
    MEDIA_INFO_LOG("Location_InsertGeoKnowledge_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryLocationTest, Location_InsertGeoKnowledge_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Location_InsertGeoKnowledge_Test_002::Start");
    Uri geoKnowledgeUri(URI_GEO_KEOWLEDGE);
    MediaLibraryCommand cmd(geoKnowledgeUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(LATITUDE, 31.3211254555);
    valuesBucket.Put(LONGITUDE, 120.12356458855);
    valuesBucket.Put(LOCATION_KEY, 141189990037);
    valuesBucket.Put(LANGUAGE, "zh");
    valuesBucket.Put(COUNTRY, "中国");
    valuesBucket.Put(ADMIN_AREA, "江苏省");
    valuesBucket.Put(CITY_ID, "12115546546521");
    valuesBucket.Put(LOCALITY, "淮安市");
    valuesBucket.Put(SUB_LOCALITY, "姑苏区");
    valuesBucket.Put(THOROUGHFARE, "人民路");
    valuesBucket.Put(SUB_THOROUGHFARE, "1285号");
    valuesBucket.Put(FEATURE_NAME, "人民路辅路苏州国美电器人名路旗舰店");
    valuesBucket.Put(CITY_NAME, "淮安市");
    valuesBucket.Put(ADDRESS_DESCRIPTION, "中国江苏省淮安市姑苏区人民路辅路苏州国美电器人名路旗舰店");
    auto retVal1 = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    auto retVal2 = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    DataShare::DataShareValuesBucket valuesBucket2;
    EXPECT_GT(retVal1, 0);
    EXPECT_EQ(retVal2, E_HAS_DB_ERROR);
    MEDIA_INFO_LOG("Location_InsertGeoKnowledge_Test_002::retVal = %{public}d. retVal2 = %{public}d. End",
        retVal1, retVal2);
}

HWTEST_F(MediaLibraryLocationTest, Location_UpdateGeoKnowledge_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Location_UpdateGeoKnowledge_Test_001::Start");
    Uri geoKnowledgeUri(URI_GEO_KEOWLEDGE);
    MediaLibraryCommand cmd(geoKnowledgeUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(LATITUDE, 31.3107738494873);
    valuesBucket.Put(LONGITUDE, 120.6175308227539);
    valuesBucket.Put(LOCATION_KEY, 141189990037);
    valuesBucket.Put(LANGUAGE, "en");
    valuesBucket.Put(COUNTRY, "China");
    valuesBucket.Put(ADMIN_AREA, "Jiangsu");
    valuesBucket.Put(CITY_ID, "123456789101232");
    valuesBucket.Put(LOCALITY, "Suzhou");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    DataShare::DataShareValuesBucket updateValues;
    updateValues.Put(ADMIN_AREA, "Shanghai");
    updateValues.Put(LOCALITY, "shanghai");
    DataShare::DataSharePredicates predicates;
    vector<string> inValues;
    inValues.push_back("141189990037");
    inValues.push_back("140877099576");
    predicates.In(LOCATION_KEY, inValues);
    auto retVal = MediaLibraryDataManager::GetInstance()->Update(cmd, updateValues, predicates);
    EXPECT_EQ((retVal == 1), true);
    vector<string> columns;
    columns.push_back(ADMIN_AREA);
    columns.push_back(LOCALITY);
    int errCode = 0;
    auto queryResultSet = MediaLibraryDataManager::GetInstance()->Query(cmd, columns, predicates, errCode);
    shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>(queryResultSet);
    int count;
    resultSet->GetRowCount(count);
    EXPECT_GT(count, 0);
    resultSet->GoToFirstRow();
    string adminArea;
    string locality;
    resultSet->GetString(0, adminArea);
    resultSet->GetString(1, locality);
    MEDIA_INFO_LOG("Location_UpdateGeoKnowledge_Test_001::adminArea = %{public}s locality = %{public}s. End",
        adminArea.c_str(), locality.c_str());
}

HWTEST_F(MediaLibraryLocationTest, Location_DeleteGeoKnowledge_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Location_DeleteGeoKnowledge_Test_001::Start");
    Uri geoKnowledgeUri(URI_GEO_KEOWLEDGE);
    MediaLibraryCommand cmd(geoKnowledgeUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(LATITUDE, 31.123255565444);
    valuesBucket.Put(LONGITUDE, 120.123454565544);
    valuesBucket.Put(LOCATION_KEY, 12354648855);
    valuesBucket.Put(LANGUAGE, "en");
    valuesBucket.Put(COUNTRY, "China");
    valuesBucket.Put(ADMIN_AREA, "Jiangsu");
    valuesBucket.Put(LOCALITY, "Suzhou");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    DataShare::DataSharePredicates predicates;
    vector<string> inValues;
    inValues.push_back("12354648855");
    inValues.push_back("140877099576");
    predicates.In(LOCATION_KEY, inValues);
    auto retVal = MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates);
    EXPECT_EQ((retVal == 1), true);
    MEDIA_INFO_LOG("Location_DeleteOcr_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryLocationTest, Location_InsertGeoDictionary_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Location_InsertGeoDictionary_Test_001::Start");
    Uri geoKnowDictionaryUri(URI_GEO_DICTIONARY);
    MediaLibraryCommand cmd(geoKnowDictionaryUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(CITY_ID, "123456789123456789");
    valuesBucket.Put(LANGUAGE, "zh");
    valuesBucket.Put(CITY_NAME, "江苏");
    auto retVal = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    EXPECT_GT(retVal, 0);
    MEDIA_INFO_LOG("Location_InsertGeoDictionary_Test_001::retVal = %{public}d. End", retVal);
}

HWTEST_F(MediaLibraryLocationTest, Location_InsertGeoDictionary_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Location_InsertGeoDictionary_Test_002::Start");
    Uri geoKnowDictionaryUri(URI_GEO_DICTIONARY);
    MediaLibraryCommand cmd(geoKnowDictionaryUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(CITY_ID, "123456789123456789");
    valuesBucket.Put(LANGUAGE, "zh");
    valuesBucket.Put(CITY_NAME, "江苏");
    auto retVal1 = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    auto retVal2 = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    EXPECT_GT(retVal1, 0);
    EXPECT_EQ(retVal2, E_HAS_DB_ERROR);
    MEDIA_INFO_LOG("Location_InsertGeoDictionary_Test_002::retVal = %{public}d. retVal2 = %{public}d. End",
        retVal1, retVal2);
}

HWTEST_F(MediaLibraryLocationTest, Location_UpdateGeoDictionary_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Location_UpdateGeoDictionary_Test_001::Start");
    Uri geoKnowDictionaryUri(URI_GEO_DICTIONARY);
    MediaLibraryCommand cmd(geoKnowDictionaryUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(CITY_ID, "123456789123456789");
    valuesBucket.Put(LANGUAGE, "en");
    valuesBucket.Put(CITY_NAME, "Jiangsu");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    DataShare::DataShareValuesBucket updateValues;
    updateValues.Put(CITY_NAME, "Shanghai");
    DataShare::DataSharePredicates predicates;
    vector<string> inValues;
    inValues.push_back("123456789123456789");
    inValues.push_back("987654321987654321");
    predicates.In(CITY_ID, inValues);
    predicates.And();
    predicates.EqualTo(LANGUAGE, "en");
    auto retVal = MediaLibraryDataManager::GetInstance()->Update(cmd, updateValues, predicates);
    EXPECT_EQ((retVal == 1), true);
    vector<string> columns;
    columns.push_back(CITY_NAME);
    int errCode = 0;
    auto queryResultSet = MediaLibraryDataManager::GetInstance()->Query(cmd, columns, predicates, errCode);
    shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>(queryResultSet);
    int count;
    resultSet->GetRowCount(count);
    EXPECT_GT(count, 0);
    resultSet->GoToFirstRow();
    string cityName;
    resultSet->GetString(0, cityName);
    MEDIA_INFO_LOG("Location_UpdateGeoDictionary_Test_001::cityName = %{public}s. End", cityName.c_str());
}

HWTEST_F(MediaLibraryLocationTest, Location_DeleteGeoDictionary_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Location_DeleteGeoDictionary_Test_001::Start");
    Uri geoKnowDictionaryUri(URI_GEO_DICTIONARY);
    MediaLibraryCommand cmd(geoKnowDictionaryUri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(CITY_ID, "123456789123456789");
    valuesBucket.Put(LANGUAGE, "en");
    valuesBucket.Put(CITY_NAME, "Jiangsu");
    MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    DataShare::DataSharePredicates predicates;
    vector<string> inValues;
    inValues.push_back("123456789123456789");
    inValues.push_back("987654321987654321");
    predicates.In(CITY_ID, inValues);
    auto retVal = MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates);
    EXPECT_EQ((retVal == 1), true);
    MEDIA_INFO_LOG("Location_DeleteGeoDictionary_Test_001::retVal = %{public}d. End", retVal);
}
} // namespace OHOS
} // namespace Media
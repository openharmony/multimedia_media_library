/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "mtp_data_utils_unit_test.h"
#include "mtp_data_utils.h"
#include "media_mtp_utils.h"
#include "datashare_result_set.h"
#include "userfile_manager_types.h"
#include "mtp_constants.h"
#include "medialibrary_errno.h"
#include "property.h"
#include <vector>
#include <string>
#include <variant>
#include "header_data.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
const uint16_t MTP_FORMAT_TEST_CODE = 0x3100;

void MtpDataUtilsUnitTest::SetUpTestCase(void) {}
void MtpDataUtilsUnitTest::TearDownTestCase(void) {}
void MtpDataUtilsUnitTest::SetUp() {}
void MtpDataUtilsUnitTest::TearDown(void) {}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SolveHandlesFormatData
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_001, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    uint16_t format = MTP_FORMAT_HTML_CODE;
    std::string outExtension = "";
    MediaType outMediaType;
    mtpDataUtils->SolveHandlesFormatData(format, outExtension, outMediaType);
    EXPECT_EQ(outMediaType, MEDIA_TYPE_DEFAULT);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SolveHandlesFormatData
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_002, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    uint16_t format = MTP_FORMAT_ABSTRACT_AUDIO_PLAYLIST_CODE;
    std::string outExtension = "";
    MediaType outMediaType;
    mtpDataUtils->SolveHandlesFormatData(format, outExtension, outMediaType);
    EXPECT_EQ(outMediaType, MEDIA_TYPE_AUDIO);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SolveHandlesFormatData
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_003, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    uint16_t format = MTP_FORMAT_TEST_CODE;
    std::string outExtension = "";
    MediaType outMediaType;
    int32_t res = mtpDataUtils->SolveHandlesFormatData(format, outExtension, outMediaType);
    EXPECT_EQ(res, MTP_ERROR_INVALID_OBJECTHANDLE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SolveSendObjectFormatData
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_004, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    uint16_t format = MTP_FORMAT_TEST_CODE;
    MediaType outMediaType;
    mtpDataUtils->SolveSendObjectFormatData(format, outMediaType);
    EXPECT_EQ(outMediaType, MEDIA_TYPE_FILE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SolveSendObjectFormatData
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_005, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    uint16_t format = MTP_FORMAT_GIF_CODE;
    MediaType outMediaType;
    mtpDataUtils->SolveSendObjectFormatData(format, outMediaType);
    EXPECT_EQ(outMediaType, MEDIA_TYPE_IMAGE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SolveSetObjectPropValueData
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_006, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->property = MTP_PROPERTY_ASSOCIATION_TYPE_CODE;
    std::string outColName = "";
    variant<int64_t, std::string> outColVal;
    int32_t res = mtpDataUtils->SolveSetObjectPropValueData(context, outColName, outColVal);
    EXPECT_EQ(res, MTP_ERROR_INVALID_OBJECTPROP_VALUE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SolveSetObjectPropValueData
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_007, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->property = MTP_PROPERTY_PARENT_OBJECT_CODE;
    context->properType = MTP_TYPE_STRING_CODE;
    std::string outColName = "";
    variant<int64_t, std::string> outColVal;
    int32_t res = mtpDataUtils->SolveSetObjectPropValueData(context, outColName, outColVal);
    EXPECT_EQ(res, MTP_SUCCESS);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SolveSetObjectPropValueData
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_008, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->property = MTP_PROPERTY_PARENT_OBJECT_CODE;
    context->properType = MTP_TYPE_AUINT128_CODE;
    std::string outColName = "";
    variant<int64_t, std::string> outColVal;
    int32_t res = mtpDataUtils->SolveSetObjectPropValueData(context, outColName, outColVal);
    EXPECT_EQ(res, MTP_SUCCESS);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetMediaTypeByformat
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_009, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    uint16_t format = MTP_FORMAT_TEST_CODE;
    MediaType outMediaType;
    mtpDataUtils->GetMediaTypeByformat(format, outMediaType);
    EXPECT_EQ(outMediaType, MEDIA_TYPE_DEFAULT);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetMediaTypeByformat
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_010, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    uint16_t format = MTP_FORMAT_BMP_CODE;
    MediaType outMediaType;
    mtpDataUtils->GetMediaTypeByformat(format, outMediaType);
    EXPECT_EQ(outMediaType, MEDIA_TYPE_IMAGE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetPropListBySet
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_011, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->property = MTP_PROPERTY_ALL_CODE;
    context->format = MTP_FORMAT_PNG_CODE;
    std::shared_ptr<DataShare::DataShareResultSet> resultSet = std::make_shared<DataShare::DataShareResultSet>();
    ASSERT_NE(resultSet, nullptr);
    shared_ptr<vector<Property>> outProps = std::make_shared<vector<Property>>();
    ASSERT_NE(outProps, nullptr);
    int32_t res = mtpDataUtils->GetPropListBySet(context, resultSet, outProps);
    EXPECT_EQ(res, MTP_ERROR_INVALID_OBJECTHANDLE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetPropListBySet
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_012, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->property = MTP_PROPERTY_STORAGE_ID_CODE;
    std::shared_ptr<DataShare::DataShareResultSet> resultSet = std::make_shared<DataShare::DataShareResultSet>();
    ASSERT_NE(resultSet, nullptr);
    shared_ptr<vector<Property>> outProps = std::make_shared<vector<Property>>();
    ASSERT_NE(outProps, nullptr);
    int32_t res = mtpDataUtils->GetPropListBySet(context, resultSet, outProps);
    EXPECT_EQ(res, MTP_ERROR_INVALID_OBJECTHANDLE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetMovingOrEnditOneRowPropList
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_013, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->property = MTP_PROPERTY_STORAGE_ID_CODE;
    std::shared_ptr<UInt16List> properties = std::make_shared<UInt16List>();
    properties->push_back(MTP_PROPERTY_OBJECT_FORMAT_CODE);
    properties->push_back(MTP_PROPERTY_OBJECT_SIZE_CODE);
    properties->push_back(MTP_PROPERTY_OBJECT_FILE_NAME_CODE);
    properties->push_back(MTP_PROPERTY_ALBUM_NAME_CODE);
    properties->push_back(MTP_PROPERTY_PROTECTION_STATUS_CODE);
    properties->push_back(MTP_PROPERTY_NAME_CODE);
    MovingType movingType;
    std::string path = "";
    shared_ptr<vector<Property>> outProps = std::make_shared<vector<Property>>();
    ASSERT_NE(outProps, nullptr);
    mtpDataUtils->GetMovingOrEnditOneRowPropList(properties, path, context, outProps, movingType);
    EXPECT_FALSE(outProps->empty());
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: ReturnError
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_014, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    std::string errMsg = "";
    ResultSetDataType type = TYPE_STRING;
    variant<int32_t, int64_t, std::string> res = mtpDataUtils->ReturnError(errMsg, type);
    EXPECT_EQ(std::get<std::string>(res), "");
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: ReturnError
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_015, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    std::string errMsg = "";
    ResultSetDataType type = TYPE_INT32;
    variant<int32_t, int64_t, std::string> res = mtpDataUtils->ReturnError(errMsg, type);
    EXPECT_EQ(std::get<int32_t>(res), 0);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetFormatByPath
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_016, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    std::string path = "";
    uint16_t outFormat = 0;
    mtpDataUtils->GetFormatByPath(path, outFormat);
    EXPECT_NE(outFormat, MTP_FORMAT_ASSOCIATION_CODE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetFormatByPath
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_018, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    std::string path = "/storage/media/100/local/files/Docs/Desktop/1.txt";
    uint16_t outFormat = 0;
    mtpDataUtils->GetFormatByPath(path, outFormat);
    EXPECT_EQ(outFormat, MTP_FORMAT_TEXT_CODE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetFormat
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_019, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    std::shared_ptr<DataShare::DataShareResultSet> resultSet = std::make_shared<DataShare::DataShareResultSet>();
    ASSERT_NE(resultSet, nullptr);
    uint16_t outFormat = 0;
    int32_t res = mtpDataUtils->GetFormat(resultSet, outFormat);
    EXPECT_EQ(res, E_FAIL);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetPropValueBySet
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_020, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    uint32_t property = MTP_PROPERTY_NAME_CODE;
    PropertyValue outPropValue;
    std::shared_ptr<DataShare::DataShareResultSet> resultSet = std::make_shared<DataShare::DataShareResultSet>();
    ASSERT_NE(resultSet, nullptr);
    int32_t res = mtpDataUtils->GetPropValueBySet(property, resultSet, outPropValue);
    EXPECT_EQ(res, MTP_ERROR_INVALID_OBJECTHANDLE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetMediaTypeByName
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_021, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    std::string displayName = "1.txt";
    MediaType outMediaType;
    mtpDataUtils->GetMediaTypeByName(displayName, outMediaType);
    EXPECT_EQ(outMediaType, MEDIA_TYPE_DEFAULT);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetMediaTypeByName
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_022, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    std::string displayName = "Desktop";
    MediaType outMediaType;
    int32_t res = mtpDataUtils->GetMediaTypeByName(displayName, outMediaType);
    EXPECT_EQ(res, E_SUCCESS);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetMediaTypeByName
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_023, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    std::string displayName = "1.dng";
    MediaType outMediaType;
    mtpDataUtils->GetMediaTypeByName(displayName, outMediaType);
    EXPECT_EQ(outMediaType, MEDIA_TYPE_IMAGE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetMediaTypeByName
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_024, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    std::string displayName = "1.mp4v";
    MediaType outMediaType;
    mtpDataUtils->GetMediaTypeByName(displayName, outMediaType);
    EXPECT_EQ(outMediaType, MEDIA_TYPE_VIDEO);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetMtpPropList
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_025, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    std::shared_ptr<std::unordered_map<uint32_t, std::string>> handles =
        std::make_shared<std::unordered_map<uint32_t, std::string>>();
    ASSERT_NE(handles, nullptr);
    std::unordered_map<std::string, uint32_t> pathHandles;
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    std::shared_ptr<vector<Property>> outProps = std::make_shared<vector<Property>>();
    ASSERT_NE(outProps, nullptr);
    int32_t res = mtpDataUtils->GetMtpPropList(handles, pathHandles, context, outProps);
    EXPECT_EQ(res, MTP_SUCCESS);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetMtpPropList
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_026, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    std::shared_ptr<std::unordered_map<uint32_t, std::string>> handles =
        std::make_shared<std::unordered_map<uint32_t, std::string>>();
    ASSERT_NE(handles, nullptr);
    std::unordered_map<std::string, uint32_t> pathHandles;
    std::shared_ptr<MtpOperationContext> context = nullptr;
    std::shared_ptr<vector<Property>> outProps = std::make_shared<vector<Property>>();
    ASSERT_NE(outProps, nullptr);
    int32_t res = mtpDataUtils->GetMtpPropList(handles, pathHandles, context, outProps);
    EXPECT_EQ(res, MTP_ERROR_INVALID_OBJECTHANDLE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetMtpPropList
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_027, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    std::shared_ptr<std::unordered_map<uint32_t, std::string>> handles = nullptr;
    std::unordered_map<std::string, uint32_t> pathHandles;
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    std::shared_ptr<vector<Property>> outProps = std::make_shared<vector<Property>>();
    ASSERT_NE(outProps, nullptr);
    int32_t res = mtpDataUtils->GetMtpPropList(handles, pathHandles, context, outProps);
    EXPECT_EQ(res, MTP_ERROR_INVALID_OBJECTHANDLE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetMtpPropValue
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_028, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    std::string path = "";
    uint32_t property = MTP_PROPERTY_STORAGE_ID_CODE;
    uint16_t format = 0;
    PropertyValue outPropValue;
    int32_t res = mtpDataUtils->GetMtpPropValue(path, property, format, outPropValue);
    EXPECT_EQ(res, MTP_ERROR_INVALID_OBJECTPROP_VALUE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetMtpPropValue
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_029, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    std::string path = "";
    uint32_t property = MTP_PROPERTY_OBJECT_FORMAT_CODE;
    uint16_t format = 0;
    PropertyValue outPropValue;
    int32_t res = mtpDataUtils->GetMtpPropValue(path, property, format, outPropValue);
    EXPECT_EQ(res, MTP_ERROR_INVALID_OBJECTPROP_VALUE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetMtpPropValue
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_030, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    std::string path = "";
    uint32_t property = MTP_PROPERTY_OBJECT_FILE_NAME_CODE;
    uint16_t format = 0;
    PropertyValue outPropValue;
    int32_t res = mtpDataUtils->GetMtpPropValue(path, property, format, outPropValue);
    EXPECT_EQ(res, MTP_SUCCESS);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetMtpFormatByPath
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_034, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    std::string path = "";
    uint16_t outFormat = 0;
    PropertyValue outPropValue;
    uint32_t res = mtpDataUtils->GetMtpFormatByPath(path, outFormat);
    EXPECT_EQ(res, MTP_ERROR_INVALID_OBJECTPROP_VALUE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetMovingOrEnditSourcePath
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_036, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    std::string path = "/storage/media/100/local/files/Docs/Desktop/1.jpg";
    int32_t subtype = static_cast<int32_t>(PhotoSubType::MOVING_PHOTO);
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->handle = 2 * COMMON_PHOTOS_OFFSET;
    std::string res = mtpDataUtils->GetMovingOrEnditSourcePath(path, subtype, context);
    EXPECT_EQ(res, "");
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetMovingOrEnditSourcePath
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_037, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    std::string path = "/storage/media/100/local/files/Docs/Desktop/1.jpg";
    int32_t subtype = static_cast<int32_t>(PhotoSubType::CAMERA);
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->handle = 2 * COMMON_PHOTOS_OFFSET;
    std::string res = mtpDataUtils->GetMovingOrEnditSourcePath(path, subtype, context);
    EXPECT_EQ(res, "");
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetMovingOrEnditSourcePath
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_038, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    std::string path = "/storage/media/100/local/files/Docs/Desktop/1.jpg";
    int32_t subtype = static_cast<int32_t>(PhotoSubType::CAMERA);
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->handle = 3 * COMMON_PHOTOS_OFFSET;
    std::string res = mtpDataUtils->GetMovingOrEnditSourcePath(path, subtype, context);
    EXPECT_NE(res, "");
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetMovingOrEnditSourcePath
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_039, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    std::string path = "/storage/media/100/local/files/Docs/Desktop/1.jpg";
    int32_t subtype = static_cast<int32_t>(PhotoSubType::CAMERA);
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->handle = 4 * COMMON_PHOTOS_OFFSET;
    std::string res = mtpDataUtils->GetMovingOrEnditSourcePath(path, subtype, context);
    EXPECT_EQ(res, "");
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetMovingOrEnditSourcePath
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_040, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    std::string path = "/storage/media/100/local/files/Docs/Desktop/1.jpg";
    int32_t subtype = static_cast<int32_t>(PhotoSubType::CAMERA);
    std::shared_ptr<MtpOperationContext> context = std::make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    context->handle = 5 * COMMON_PHOTOS_OFFSET;
    std::string res = mtpDataUtils->GetMovingOrEnditSourcePath(path, subtype, context);
    EXPECT_EQ(res, "");
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetOneRowPropList
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_041, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    uint32_t handle = 1;
    std::shared_ptr<DataShare::DataShareResultSet> resultSet = std::make_shared<DataShare::DataShareResultSet>();
    ASSERT_NE(resultSet, nullptr);
    std::shared_ptr<UInt16List> properties = std::make_shared<UInt16List>();
    ASSERT_NE(properties, nullptr);
    properties->push_back(MTP_PROPERTY_OBJECT_FORMAT_CODE);
    properties->push_back(MTP_PROPERTY_OBJECT_SIZE_CODE);
    properties->push_back(MTP_PROPERTY_STORAGE_ID_CODE);
    std::shared_ptr<vector<Property>> outProps = std::make_shared<vector<Property>>();
    ASSERT_NE(outProps, nullptr);
    mtpDataUtils->GetOneRowPropList(handle, resultSet, properties, outProps);
    EXPECT_FALSE(outProps->empty());
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SetOneDefaultlPropList
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_042, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    uint32_t handle = 1;
    uint16_t property = MTP_PROPERTY_STORAGE_ID_CODE;
    std::shared_ptr<vector<Property>> outProps = std::make_shared<vector<Property>>();
    ASSERT_NE(outProps, nullptr);
    mtpDataUtils->SetOneDefaultlPropList(handle, property, outProps);
    EXPECT_FALSE(outProps->empty());
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SetOneDefaultlPropList
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_043, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    uint32_t handle = 1;
    uint16_t property = MTP_PROPERTY_PROTECTION_STATUS_CODE;
    std::shared_ptr<vector<Property>> outProps = std::make_shared<vector<Property>>();
    ASSERT_NE(outProps, nullptr);
    mtpDataUtils->SetOneDefaultlPropList(handle, property, outProps);
    EXPECT_FALSE(outProps->empty());
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SetOneDefaultlPropList
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_044, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    uint32_t handle = 1;
    uint16_t property = MTP_PROPERTY_PERSISTENT_UID_CODE;
    std::shared_ptr<vector<Property>> outProps = std::make_shared<vector<Property>>();
    ASSERT_NE(outProps, nullptr);
    mtpDataUtils->SetOneDefaultlPropList(handle, property, outProps);
    EXPECT_FALSE(outProps->empty());
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SetOneDefaultlPropList
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_045, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    uint32_t handle = 1;
    uint16_t property = MTP_PROPERTY_ALBUM_NAME_CODE;
    std::shared_ptr<vector<Property>> outProps = std::make_shared<vector<Property>>();
    ASSERT_NE(outProps, nullptr);
    mtpDataUtils->SetOneDefaultlPropList(handle, property, outProps);
    EXPECT_FALSE(outProps->empty());
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SetOneDefaultlPropList
 */
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_046, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    uint32_t handle = 1;
    uint16_t property = MTP_PROPERTY_ALBUM_NAME_CODE;
    std::shared_ptr<vector<Property>> outProps = std::make_shared<vector<Property>>();
    ASSERT_NE(outProps, nullptr);
    mtpDataUtils->SetOneDefaultlPropList(handle, property, outProps);
    EXPECT_FALSE(outProps->empty());
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetContainerLength
 */
HWTEST_F(MtpDataUtilsUnitTest, mtp_header_data_001, TestSize.Level0)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    context->format = 0;
    context->parent = 1;
    shared_ptr<HeaderData> headerData = make_shared<HeaderData>(context);
    headerData->Reset();
    headerData->SetCode(0);
    headerData->SetContainerType(0);
    uint32_t len = headerData->GetContainerLength();
    EXPECT_EQ(len == 0, true);
    headerData->SetTransactionId(1);
    uint32_t id = headerData->GetTransactionId();
    EXPECT_EQ(id == 1, true);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SetProperty
 */
HWTEST_F(MtpDataUtilsUnitTest, mtp_data_utils_test_001, TestSize.Level0)
{
    string column = "SetPropert";
    shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<DataShare::DataShareResultSet>();
    Property prop;
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    ResultSetDataType type = TYPE_NULL;
    mtpDataUtils->SetProperty(column, resultSet, type, prop);
    ResultSetDataType typeOne = TYPE_STRING;
    mtpDataUtils->SetProperty(column, resultSet, typeOne, prop);
    ResultSetDataType typeTwo = TYPE_INT32;
    mtpDataUtils->SetProperty(column, resultSet, typeTwo, prop);
    ResultSetDataType typeThree = TYPE_INT64;
    mtpDataUtils->SetProperty(column, resultSet, typeThree, prop);
    uint16_t outFormat = 0;
    mtpDataUtils->GetFormatByPath("", outFormat);
    string path = "/data";
    mtpDataUtils->GetFormatByPath(path, outFormat);
    EXPECT_EQ(outFormat, MTP_FORMAT_ASSOCIATION_CODE);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SetMtpProperty
 */
HWTEST_F(MtpDataUtilsUnitTest, mtp_data_utils_test_002, TestSize.Level0)
{
    string column = MEDIA_DATA_DB_NAME;
    string path = "/data";
    Property prop;
    ResultSetDataType type = TYPE_NULL;
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    mtpDataUtils->SetMtpProperty(column, path, type, prop);
    column = MEDIA_DATA_DB_SIZE;
    mtpDataUtils->SetMtpProperty(column, path, type, prop);
    column = MEDIA_DATA_DB_DATE_MODIFIED;
    mtpDataUtils->SetMtpProperty(column, path, type, prop);
    column = MEDIA_DATA_DB_DATE_ADDED;
    mtpDataUtils->SetMtpProperty(column, path, type, prop);
    column = MEDIA_DATA_DB_DESCRIPTION;
    mtpDataUtils->SetMtpProperty(column, path, type, prop);
    column = MEDIA_DATA_DB_DURATION;
    mtpDataUtils->SetMtpProperty(column, path, type, prop);
    column = MEDIA_DATA_DB_ARTIST;
    mtpDataUtils->SetMtpProperty(column, path, type, prop);
    column = MEDIA_DATA_DB_ALBUM_NAME;
    mtpDataUtils->SetMtpProperty(column, path, type, prop);
    string MEDIA_DATA_DB_COMPOSER = "composer";
    column = MEDIA_DATA_DB_COMPOSER;
    mtpDataUtils->SetMtpProperty(column, path, type, prop);
    path = "";
    mtpDataUtils->SetMtpProperty(column, path, type, prop);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SetMtpOneDefaultlPropList
 */
HWTEST_F(MtpDataUtilsUnitTest, mtp_data_utils_test_003, TestSize.Level0)
{
    std::shared_ptr<vector<Property>> outProps = std::make_shared<vector<Property>>();
    ASSERT_NE(outProps, nullptr);
    uint32_t handle = 0;
    uint16_t property = MTP_PROPERTY_STORAGE_ID_CODE;
    int32_t storageId = 0;
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    mtpDataUtils->SetMtpOneDefaultlPropList(handle, property, outProps, storageId);
    property = MTP_PROPERTY_PROTECTION_STATUS_CODE;
    mtpDataUtils->SetMtpOneDefaultlPropList(handle, property, outProps, storageId);
    property = MTP_PROPERTY_PERSISTENT_UID_CODE;
    mtpDataUtils->SetMtpOneDefaultlPropList(handle, property, outProps, storageId);
    property = MTP_PROPERTY_ALBUM_NAME_CODE;
    mtpDataUtils->SetMtpOneDefaultlPropList(handle, property, outProps, storageId);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetMtpPropValue
 */
HWTEST_F(MtpDataUtilsUnitTest, mtp_data_utils_test_004, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    std::string path = "/data";
    uint32_t property = MTP_PROPERTY_OBJECT_FILE_NAME_CODE;
    uint16_t format = 0;
    PropertyValue outPropValue;
    int32_t res = mtpDataUtils->GetMtpPropValue(path, property, format, outPropValue);
    EXPECT_EQ(res, MTP_SUCCESS);
    property = MTP_PROPERTY_DATE_MODIFIED_CODE;
    res = mtpDataUtils->GetMtpPropValue(path, property, format, outPropValue);
    EXPECT_EQ(res, MTP_SUCCESS);
    property = MTP_PROPERTY_NAME_CODE;
    res = mtpDataUtils->GetMtpPropValue(path, property, format, outPropValue);
    EXPECT_EQ(res, MTP_SUCCESS);
    property = MTP_PROPERTY_DATE_ADDED_CODE;
    res = mtpDataUtils->GetMtpPropValue(path, property, format, outPropValue);
    EXPECT_EQ(res, MTP_SUCCESS);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SetPtpProperty
 */
HWTEST_F(MtpDataUtilsUnitTest, mtp_data_utils_test_005, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    string column = MEDIA_DATA_DB_PARENT_ID;
    string path = "";
    MovingType movingType;
    movingType.displayName = "test";
    movingType.parent = 1;
    Property prop;
    mtpDataUtils->SetPtpProperty(column, path, movingType, prop);
    path = "/data";
    column = MEDIA_DATA_DB_SIZE;
    mtpDataUtils->SetPtpProperty(column, path, movingType, prop);
    column = MEDIA_DATA_DB_DATE_MODIFIED;
    mtpDataUtils->SetPtpProperty(column, path, movingType, prop);
    column = MEDIA_DATA_DB_DATE_ADDED;
    mtpDataUtils->SetPtpProperty(column, path, movingType, prop);
}

} // namespace Media
} // namespace OHOS
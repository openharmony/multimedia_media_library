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
#include "datashare_result_set.h"
#include "userfile_manager_types.h"
#include "mtp_constants.h"
#include "medialibrary_errno.h"
#include "property.h"
#include <vector>
#include <string>
#include <variant>

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
HWTEST_F(MtpDataUtilsUnitTest, medialibrary_MTP_message_testlevel_0_0_017, TestSize.Level0)
{
    std::shared_ptr<MtpDataUtils> mtpDataUtils = std::make_shared<MtpDataUtils>();
    ASSERT_NE(mtpDataUtils, nullptr);
    std::string path = "/storage/media/100/local/files/Docs/Desktop";
    uint16_t outFormat = 0;
    mtpDataUtils->GetFormatByPath(path, outFormat);
    EXPECT_EQ(outFormat, MTP_FORMAT_ASSOCIATION_CODE);
}
} // namespace Media
} // namespace OHOS
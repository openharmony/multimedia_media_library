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

#include "media_library_cloud_data_client_inner_api_test.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <utime.h>
#include <fstream>
#include "i_cloud_media_data_handler.h"
#include "cloud_media_data_handler.h"
#include "medialibrary_errno.h"
#include "cloud_check_data.h"
#include "cloud_file_data.h"
#include "cloud_media_data_client.h"
#include "cloud_media_data_handler.h"
#include "cloud_meta_data.h"
#include "json/json.h"
#include "media_log.h"
#include "mdk_asset.h"
#include "mdk_database.h"
#include "mdk_error.h"
#include "mdk_record_field.h"
#include "mdk_record.h"
#include "mdk_reference.h"
#include "mdk_record_photos_data.h"
#include "media_operate_result.h"

using namespace testing::ext;
using namespace testing::internal;

namespace OHOS::Media::CloudSync {

void CloudMediaDataClientInnerApiTest::SetUpTestCase(void)
{
    GTEST_LOG_(INFO) << "CloudMediaDataClientInnerApiTest SetUpTestCase";
}

void CloudMediaDataClientInnerApiTest::TearDownTestCase(void)
{
    GTEST_LOG_(INFO) << "CloudMediaDataClientInnerApiTest TearDownTestCase";
}

// SetUp:Execute before each test case
void CloudMediaDataClientInnerApiTest::SetUp()
{
    GTEST_LOG_(INFO) << "CloudMediaDataClientInnerApiTest SetUp";
}

void CloudMediaDataClientInnerApiTest::TearDown(void)
{
    GTEST_LOG_(INFO) << "CloudMediaDataClientInnerApiTest TearDown";
}

HWTEST_F(CloudMediaDataClientInnerApiTest, OnStartSync_EMPTY, TestSize.Level1)
{
    std::shared_ptr<CloudMediaDataHandler> dataHandler = std::make_shared<CloudMediaDataHandler>();
    ASSERT_TRUE(dataHandler);
    EXPECT_EQ(dataHandler->OnStartSync(), E_IPC_INVAL_ARG);
}

HWTEST_F(CloudMediaDataClientInnerApiTest, OnCompleteSync_EMPTY, TestSize.Level1)
{
    std::shared_ptr<CloudMediaDataHandler> dataHandler = std::make_shared<CloudMediaDataHandler>();
    ASSERT_TRUE(dataHandler);
    EXPECT_EQ(dataHandler->OnCompleteSync(), E_IPC_INVAL_ARG);
}

HWTEST_F(CloudMediaDataClientInnerApiTest, OnCompletePush_EMPTY, TestSize.Level1)
{
    std::shared_ptr<CloudMediaDataHandler> dataHandler = std::make_shared<CloudMediaDataHandler>();
    ASSERT_TRUE(dataHandler);
    EXPECT_EQ(dataHandler->OnCompletePush(), E_IPC_INVAL_ARG);
}

HWTEST_F(CloudMediaDataClientInnerApiTest, OnCompleteCheck_EMPTY, TestSize.Level1)
{
    std::shared_ptr<CloudMediaDataHandler> dataHandler = std::make_shared<CloudMediaDataHandler>();
    ASSERT_TRUE(dataHandler);
    EXPECT_EQ(dataHandler->OnCompleteCheck(), E_IPC_INVAL_ARG);
}

HWTEST_F(CloudMediaDataClientInnerApiTest, CloudMediaDataHandler_Test, TestSize.Level1)
{
    std::shared_ptr<CloudMediaDataHandler> dataHandler = std::make_shared<CloudMediaDataHandler>();
    ASSERT_TRUE(dataHandler);
    dataHandler->SetCloudType(0);
    EXPECT_EQ(dataHandler->GetCloudType(), 0);
    dataHandler->SetTableName("PhotoAlbum");
    EXPECT_EQ(dataHandler->GetTableName(), "PhotoAlbum");
    dataHandler->SetUserId(100);
    EXPECT_EQ(dataHandler->GetUserId(), 100);
    dataHandler->SetTraceId("test");
    EXPECT_EQ(dataHandler->GetTraceId(), "test");
}

HWTEST_F(CloudMediaDataClientInnerApiTest, MDKRecordField_BasicMethods_Test001, TestSize.Level1)
{
    int valInt = 1;
    int64_t valLong = 1;
    double valDouble = 1.0;
    bool valBool = true;

    std::shared_ptr<MDKRecordField> mdkRecordFieldInt = std::make_shared<MDKRecordField>(valInt);
    ASSERT_TRUE(mdkRecordFieldInt);
    std::shared_ptr<MDKRecordField> mdkRecordFieldLong = std::make_shared<MDKRecordField>(valLong);
    ASSERT_TRUE(mdkRecordFieldLong);
    std::shared_ptr<MDKRecordField> mdkRecordFieldDouble = std::make_shared<MDKRecordField>(valDouble);
    ASSERT_TRUE(mdkRecordFieldDouble);
    std::shared_ptr<MDKRecordField> mdkRecordFieldBool = std::make_shared<MDKRecordField>(valBool);
    ASSERT_TRUE(mdkRecordFieldBool);

    EXPECT_EQ(mdkRecordFieldInt->GetType(), MDKRecordFieldType::FIELD_TYPE_INT);
    int64_t v = std::get<int64_t>(mdkRecordFieldInt->GetFieldValue());
    EXPECT_EQ(static_cast<int>(v), valInt);
    
    MDKLocalErrorCode errorCode = mdkRecordFieldInt->GetInt(valInt);
    EXPECT_EQ(errorCode, MDKLocalErrorCode::NO_ERROR);
    errorCode = mdkRecordFieldLong->GetLong(valLong);
    EXPECT_EQ(errorCode, MDKLocalErrorCode::NO_ERROR);
    errorCode = mdkRecordFieldDouble->GetDouble(valDouble);
    EXPECT_EQ(errorCode, MDKLocalErrorCode::NO_ERROR);
    errorCode = mdkRecordFieldBool->GetBool(valBool);
    EXPECT_EQ(errorCode, MDKLocalErrorCode::NO_ERROR);
    
    int valIntConversion = static_cast<int>(*mdkRecordFieldInt);
    EXPECT_EQ(valIntConversion, valInt);
    int64_t valLongConversion = static_cast<int64_t>(*mdkRecordFieldLong);
    EXPECT_EQ(valLongConversion, valLong);
    double valDoubleConversion = static_cast<double>(*mdkRecordFieldDouble);
    EXPECT_EQ(valDoubleConversion, valDouble);
    bool valBoolConversion = static_cast<bool>(*mdkRecordFieldBool);
    EXPECT_EQ(valBoolConversion, valBool);
}

HWTEST_F(CloudMediaDataClientInnerApiTest, MDKRecordField_BasicMethods_Test002, TestSize.Level1)
{
    std::string valString = "test";
    std::vector<uint8_t> valBlob;
    std::vector<MDKRecordField> valRecordList;
    std::map<std::string, MDKRecordField> valRecordMap;

    std::shared_ptr<MDKRecordField> mdkRecordFieldString = std::make_shared<MDKRecordField>(valString);
    ASSERT_TRUE(mdkRecordFieldString);
    std::shared_ptr<MDKRecordField> mdkRecordFieldBlob = std::make_shared<MDKRecordField>(valBlob);
    ASSERT_TRUE(mdkRecordFieldBlob);
    std::shared_ptr<MDKRecordField> mdkRecordFieldRecordList = std::make_shared<MDKRecordField>(valRecordList);
    ASSERT_TRUE(mdkRecordFieldRecordList);
    std::shared_ptr<MDKRecordField> mdkRecordFieldRecordMap = std::make_shared<MDKRecordField>(valRecordMap);
    ASSERT_TRUE(mdkRecordFieldRecordMap);
    
    MDKLocalErrorCode errorCode = mdkRecordFieldString->GetString(valString);
    EXPECT_EQ(errorCode, MDKLocalErrorCode::NO_ERROR);
    errorCode = mdkRecordFieldBlob->GetBlob(valBlob);
    EXPECT_EQ(errorCode, MDKLocalErrorCode::NO_ERROR);
    errorCode = mdkRecordFieldRecordList->GetRecordList(valRecordList);
    EXPECT_EQ(errorCode, MDKLocalErrorCode::NO_ERROR);
    errorCode = mdkRecordFieldRecordMap->GetRecordMap(valRecordMap);
    EXPECT_EQ(errorCode, MDKLocalErrorCode::NO_ERROR);

    std::string valStringConversion = static_cast<std::string>(*mdkRecordFieldString);
    EXPECT_EQ(valStringConversion, valString);
    std::vector<uint8_t> valBlobConversion = static_cast<std::vector<uint8_t>>(*mdkRecordFieldBlob);
    EXPECT_EQ(valBlobConversion, valBlob);
    std::vector<MDKRecordField> valRecordListConversion =
        static_cast<std::vector<MDKRecordField>>(*mdkRecordFieldRecordList);
    EXPECT_EQ(valRecordListConversion.size(), 0);
    EXPECT_EQ(valRecordList.size(), 0);
    std::map<std::string, MDKRecordField> valRecordMapConversion =
        static_cast<std::map<std::string, MDKRecordField>>(*mdkRecordFieldRecordMap);
    EXPECT_EQ(valRecordMapConversion.size(), 0);
    EXPECT_EQ(valRecordMap.size(), 0);
}

HWTEST_F(CloudMediaDataClientInnerApiTest, MDKRecordField_BasicMethods_Test003, TestSize.Level1)
{
    MDKAsset valAsset;
    MDKReference valReference;
    MDKFieldValue valFieldValue;

    std::shared_ptr<MDKRecordField> mdkRecordFieldAsset = std::make_shared<MDKRecordField>(valAsset);
    ASSERT_TRUE(mdkRecordFieldAsset);
    std::shared_ptr<MDKRecordField> mdkRecordFieldReference = std::make_shared<MDKRecordField>(valReference);
    ASSERT_TRUE(mdkRecordFieldReference);
    std::shared_ptr<MDKRecordField> mdkRecordFieldFieldValue = std::make_shared<MDKRecordField>(valFieldValue);
    ASSERT_TRUE(mdkRecordFieldFieldValue);

    MDKLocalErrorCode errorCode = mdkRecordFieldAsset->GetAsset(valAsset);
    EXPECT_EQ(errorCode, MDKLocalErrorCode::NO_ERROR);
    errorCode = mdkRecordFieldReference->GetReference(valReference);
    EXPECT_EQ(errorCode, MDKLocalErrorCode::NO_ERROR);

    MDKAsset valAssetConversion = static_cast<MDKAsset>(*mdkRecordFieldAsset);
    EXPECT_EQ(valAssetConversion.uri, valAsset.uri);
    EXPECT_EQ(valAssetConversion.assetName, valAsset.assetName);
    EXPECT_EQ(valAssetConversion.operationType, valAsset.operationType);
    EXPECT_EQ(valAssetConversion.hash, valAsset.hash);
    EXPECT_EQ(valAssetConversion.version, valAsset.version);
    EXPECT_EQ(valAssetConversion.assetId, valAsset.assetId);
    EXPECT_EQ(valAssetConversion.subPath, valAsset.subPath);
    EXPECT_EQ(valAssetConversion.exCheckInfo, valAsset.exCheckInfo);
    EXPECT_EQ(valAssetConversion.size, valAsset.size);
    EXPECT_EQ(valAssetConversion.fd, valAsset.fd);
    MDKReference valReferenceConversion = static_cast<MDKReference>(*mdkRecordFieldReference);
    EXPECT_EQ(valReferenceConversion.recordId, valReference.recordId);
    EXPECT_EQ(valReferenceConversion.recordType, valReference.recordType);
    MDKFieldValue valFieldValueConversion = static_cast<MDKFieldValue>(*mdkRecordFieldFieldValue);
    EXPECT_EQ(valFieldValueConversion.index(), valFieldValue.index());
}

HWTEST_F(CloudMediaDataClientInnerApiTest, MDKRecordField_Json_Test, TestSize.Level1)
{
    std::shared_ptr<MDKRecordField> mdkRecordField = std::make_shared<MDKRecordField>();
    ASSERT_TRUE(mdkRecordField);
    EXPECT_EQ(mdkRecordField->ToJsonValue(), Json::nullValue);

    MDKSchemaField schemaField;
    schemaField.type = MDKRecordFieldType::FIELD_TYPE_NULL;
    EXPECT_EQ(mdkRecordField->ParseFromJsonValue(schemaField, Json::nullValue), true);
}

HWTEST_F(CloudMediaDataClientInnerApiTest, MediaOperateResult_ToString_Test, TestSize.Level1)
{
    std::shared_ptr<MediaOperateResult> mediaOperateResult = std::make_shared<MediaOperateResult>();
    ASSERT_TRUE(mediaOperateResult);
    mediaOperateResult->cloudId = "test_id";
    mediaOperateResult->errorCode = -1;
    mediaOperateResult->errorMsg = "test_msg";
    std::string str = R"({"cloudId": "test_id", "errorCode": -1", "errorMsg": "test_msg"})";
    EXPECT_EQ(mediaOperateResult->ToString(), str);
}

HWTEST_F(CloudMediaDataClientInnerApiTest, MDKError_GetErrorType_Test, TestSize.Level1)
{
    std::shared_ptr<MDKError> mdkError = std::make_shared<MDKError>();
    ASSERT_TRUE(mdkError);
    EXPECT_EQ(mdkError->GetErrorType(), MDKErrorType::TYPE_UNKNOWN);
}
}
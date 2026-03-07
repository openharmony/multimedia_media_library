/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "on_modify_file_dirty_vo.h"

#include <cstdint>
#include <gtest/gtest.h>

#include "medialibrary_errno.h"
#include <message_parcel.h>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Media::CloudSync;
using namespace OHOS::Media;

namespace OHOS::Media::CloudSync {

class OnModifyFileDirtyVoTest : public testing::Test {};

HWTEST_F(OnModifyFileDirtyVoTest, TC001_OnFileDirtyRecord_Marshalling_Unmarshalling_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致

    OnFileDirtyRecord record;
    record.cloudId = "cloud_id_123";
    record.fileId = 123;
    record.rotation = 0;
    record.fileType = 1;
    record.size = 1024;
    record.metaDateModified = 1234567890;
    record.createTime = 1234567890;
    record.modifyTime = 1234567890;
    record.path = "/storage/photo.jpg";
    record.fileName = "photo.jpg";
    record.sourcePath = "/source/photo.jpg";
    record.version = 1;
    record.serverErrorCode = 0;
    record.isSuccess = true;
    record.errorType = ErrorType::TYPE_UNKNOWN;

    OHOS::MessageParcel parcel;
    bool ret = record.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnFileDirtyRecord restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.cloudId, record.cloudId);
    EXPECT_EQ(restored.fileId, record.fileId);
    EXPECT_EQ(restored.size, record.size);
}

HWTEST_F(OnModifyFileDirtyVoTest, TC002_OnFileDirtyRecord_Marshalling_Unmarshalling_WithErrorDetails, TestSize.Level1)
{
    // 用例说明：测试基本功能；覆盖正常路径（触发条件：正常输入）；验证业务状态断言：功能正常

    OnFileDirtyRecord record;
    record.cloudId = "cloud_id_123";
    record.fileId = 123;
    record.rotation = 0;
    record.fileType = 1;
    record.size = 1024;
    record.metaDateModified = 1234567890;
    record.createTime = 1234567890;
    record.modifyTime = 1234567890;
    record.path = "/storage/photo.jpg";
    record.fileName = "photo.jpg";
    record.sourcePath = "/source/photo.jpg";
    record.version = 1;
    record.serverErrorCode = 500;
    record.isSuccess = false;
    record.errorType = static_cast<ErrorType>(1);

    CloudErrorDetail errorDetail;
    errorDetail.domain = "test_domain";
    errorDetail.reason = "test_reason";
    errorDetail.errorCode = "ERR_001";
    errorDetail.description = "Test error description";
    errorDetail.errorPos = "position";
    errorDetail.errorParam = "param";
    errorDetail.detailCode = 1;
    record.errorDetails.push_back(errorDetail);

    OHOS::MessageParcel parcel;
    bool ret = record.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnFileDirtyRecord restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.cloudId, record.cloudId);
    EXPECT_EQ(restored.errorDetails.size(), 1);
}

HWTEST_F(OnModifyFileDirtyVoTest, TC005_OnFileDirtyRecordsReqBody_Marshalling_Unmarshalling, TestSize.Level1)
{
    // 用例说明：测试基本功能；覆盖正常路径（触发条件：正常输入）；验证业务状态断言：功能正常

    OnFileDirtyRecordsReqBody reqBody;

    OnFileDirtyRecord record1;
    record1.cloudId = "cloud_id_1";
    record1.fileId = 123;
    record1.size = 1024;
    record1.path = "/storage/photo1.jpg";
    record1.fileName = "photo1.jpg";
    record1.version = 1;
    record1.serverErrorCode = 0;
    record1.isSuccess = true;
    reqBody.AddRecord(record1);

    OnFileDirtyRecord record2;
    record2.cloudId = "cloud_id_2";
    record2.fileId = 456;
    record2.size = 2048;
    record2.path = "/storage/photo2.jpg";
    record2.fileName = "photo2.jpg";
    record2.version = 2;
    record2.serverErrorCode = 0;
    record2.isSuccess = true;
    reqBody.AddRecord(record2);

    OHOS::MessageParcel parcel;
    bool ret = reqBody.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnFileDirtyRecordsReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.records.size(), 2);
    EXPECT_EQ(restored.records[0].cloudId, "cloud_id_1");
    EXPECT_EQ(restored.records[1].cloudId, "cloud_id_2");
}

HWTEST_F(OnModifyFileDirtyVoTest, TC006_OnFileDirtyRecordsReqBody_AddRecord, TestSize.Level1)
{
    // 用例说明：测试基本功能；覆盖正常路径（触发条件：正常输入）；验证业务状态断言：功能正常

    OnFileDirtyRecordsReqBody reqBody;

    OnFileDirtyRecord record;
    record.cloudId = "cloud_id_123";
    record.fileId = 123;
    record.size = 1024;
    record.path = "/storage/photo.jpg";
    record.fileName = "photo.jpg";
    record.version = 1;
    record.serverErrorCode = 0;
    record.isSuccess = true;

    auto ret = reqBody.AddRecord(record);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(reqBody.records.size(), 1);
}

}  // namespace OHOS::Media::CloudSync

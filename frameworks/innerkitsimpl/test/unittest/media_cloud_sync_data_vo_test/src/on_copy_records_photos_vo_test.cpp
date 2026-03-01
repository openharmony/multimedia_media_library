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

#include "on_copy_records_photos_vo.h"

#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Media::CloudSync;

namespace OHOS::Media::CloudSync {

class OnCopyRecordsPhotosVoTest : public testing::Test {};

HWTEST_F(OnCopyRecordsPhotosVoTest, TC001_Unmarshalling_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    OnCopyRecord record;
    record.cloudId = "cloud_id_123";
    record.fileId = 123;
    record.rotation = 0;
    record.fileType = 1;
    record.size = 1024;
    record.createTime = 1234567890;
    record.path = "/storage/test/photo.jpg";
    record.fileName = "photo.jpg";
    record.sourcePath = "/source/photo.jpg";
    record.version = 1;
    record.serverErrorCode = 0;
    record.isSuccess = true;
    record.errorType = static_cast<ErrorType>(0);

    OHOS::MessageParcel parcel;
    bool ret = record.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnCopyRecord restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.cloudId, record.cloudId);
    EXPECT_EQ(restored.fileId, record.fileId);
    EXPECT_EQ(restored.size, record.size);
    EXPECT_EQ(static_cast<int32_t>(restored.errorType), static_cast<int32_t>(record.errorType));
}

HWTEST_F(OnCopyRecordsPhotosVoTest, TC002_AddCopyRecord_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    OnCopyRecordsPhotosReqBody reqBody;

    OnCopyRecord record1;
    record1.cloudId = "cloud_id_1";
    record1.fileId = 1;
    int32_t ret = reqBody.AddCopyRecord(record1);
    EXPECT_EQ(ret, 0);

    OnCopyRecord record2;
    record2.cloudId = "cloud_id_2";
    record2.fileId = 2;
    ret = reqBody.AddCopyRecord(record2);
    EXPECT_EQ(ret, 0);

    auto records = reqBody.GetRecords();
    EXPECT_EQ(records.size(), 2);
}

HWTEST_F(OnCopyRecordsPhotosVoTest, TC003_ReqBodyMarshalling_Unmarshalling_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    OnCopyRecordsPhotosReqBody reqBody;

    OnCopyRecord record;
    record.cloudId = "cloud_id_123";
    record.fileId = 123;
    reqBody.AddCopyRecord(record);

    OHOS::MessageParcel parcel;
    bool ret = reqBody.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnCopyRecordsPhotosReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    auto records = restored.GetRecords();
    EXPECT_EQ(records.size(), 1);
    EXPECT_EQ(records[0].cloudId, record.cloudId);
}

}  // namespace OHOS::Media::CloudSync

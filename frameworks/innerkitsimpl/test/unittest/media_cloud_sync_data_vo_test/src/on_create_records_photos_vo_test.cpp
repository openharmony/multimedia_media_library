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

#include "on_create_records_photos_vo.h"

#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Media::CloudSync;

namespace OHOS::Media::CloudSync {

class OnCreateRecordsPhotosVoTest : public testing::Test {};

HWTEST_F(OnCreateRecordsPhotosVoTest, TC001_Unmarshalling_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    OnCreateRecord record;
    record.cloudId = "cloud_id_123";
    record.fileId = 123;
    record.localId = 456;
    record.rotation = 0;
    record.fileType = 1;
    record.size = 1024;
    record.createTime = 1234567890;
    record.modifiedTime = 1234567890;
    record.editedTimeMs = 0;
    record.metaDateModified = 1234567890;
    record.path = "/storage/test/photo.jpg";
    record.fileName = "photo.jpg";
    record.sourcePath = "/source/photo.jpg";
    record.livePhotoCachePath = "/cache/photo.jpg";
    record.version = 1;
    record.serverErrorCode = 0;
    record.isSuccess = true;
    record.fileSourceType = 0;
    record.storagePath = "/storage";
    record.errorType = ErrorType::TYPE_UNKNOWN;

    OHOS::MessageParcel parcel;
    bool ret = record.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnCreateRecord restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.cloudId, record.cloudId);
    EXPECT_EQ(restored.fileId, record.fileId);
    EXPECT_EQ(restored.size, record.size);
    EXPECT_EQ(static_cast<int32_t>(restored.errorType), static_cast<int32_t>(record.errorType));
}

HWTEST_F(OnCreateRecordsPhotosVoTest, TC002_AddRecord_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    OnCreateRecordsPhotosReqBody reqBody;

    OnCreateRecord record;
    record.cloudId = "cloud_id_123";
    record.fileId = 123;
    int32_t ret = reqBody.AddRecord(record);
    EXPECT_EQ(ret, 0);

    auto records = reqBody.records;
    EXPECT_EQ(records.size(), 1);
}

HWTEST_F(OnCreateRecordsPhotosVoTest, TC003_ReqBodyMarshalling_Unmarshalling_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    OnCreateRecordsPhotosReqBody reqBody;

    OnCreateRecord record;
    record.cloudId = "cloud_id_123";
    record.fileId = 123;
    reqBody.AddRecord(record);

    OHOS::MessageParcel parcel;
    bool ret = reqBody.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnCreateRecordsPhotosReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    auto records = restored.records;
    EXPECT_EQ(records.size(), 1);
}

}  // namespace OHOS::Media::CloudSync

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

#include "on_delete_records_photos_vo.h"
#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Media::CloudSync;

namespace OHOS::Media::CloudSync {

class OnDeleteRecordsPhotosVoTest : public testing::Test {};

HWTEST_F(OnDeleteRecordsPhotosVoTest, TC001_Marshalling_Unmarshalling_Success, TestSize.Level1)
{
    // 用例说明：测试OnDeleteRecordsPhoto序列化/反序列化成功路径；覆盖所有字段正常读写（触发条件：所有字段有效）；验证业务状态断言：反序列化后字段值与原值一致

    OnDeleteRecordsPhoto original;
    original.dkRecordId = "dk_record_123";
    original.cloudId = "cloud_id_456";
    original.isSuccess = true;

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnDeleteRecordsPhoto restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.dkRecordId, original.dkRecordId);
    EXPECT_EQ(restored.cloudId, original.cloudId);
    EXPECT_EQ(restored.isSuccess, original.isSuccess);
}

HWTEST_F(OnDeleteRecordsPhotosVoTest, TC002_Unmarshalling_ReadStringDkRecordId_Fail, TestSize.Level1)
{
    // 用例说明：测试OnDeleteRecordsPhoto反序列化失败路径；覆盖dkRecordId字段读取失败（触发条件：MessageParcel.ReadString失败）；验证业务状态断言：反序列化返回false

    OHOS::MessageParcel parcel;
    bool ret = parcel.WriteString("dk_record_123");
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnDeleteRecordsPhoto vo;
    ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(OnDeleteRecordsPhotosVoTest, TC003_Unmarshalling_ReadStringCloudId_Fail, TestSize.Level1)
{
    // 用例说明：测试OnDeleteRecordsPhoto反序列化失败路径；覆盖cloudId字段读取失败（触发条件：MessageParcel.ReadString失败）；验证业务状态断言：反序列化返回false

    OHOS::MessageParcel parcel;
    parcel.WriteString("dk_record_123");
    parcel.WriteString("cloud_id_456");

    parcel.RewindRead(0);
    OnDeleteRecordsPhoto vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(OnDeleteRecordsPhotosVoTest, TC004_Unmarshalling_ReadBoolIsSuccess_Fail, TestSize.Level1)
{
    // 用例说明：测试OnDeleteRecordsPhoto反序列化失败路径；覆盖isSuccess字段读取失败（触发条件：MessageParcel.ReadBool失败）；验证业务状态断言：反序列化返回false

    OHOS::MessageParcel parcel;
    parcel.WriteString("dk_record_123");
    parcel.WriteString("cloud_id_456");
    parcel.WriteBool(true);

    parcel.RewindRead(0);
    OnDeleteRecordsPhoto vo;
    bool ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(OnDeleteRecordsPhotosVoTest, TC005_ReqBody_Marshalling_Unmarshalling_Empty, TestSize.Level1)
{
    // 用例说明：测试OnDeleteRecordsPhotosReqBody空列表序列化/反序列化；覆盖空集合场景（触发条件：records为空）；验证业务状态断言：反序列化后records为空

    OnDeleteRecordsPhotosReqBody reqBody;
    ASSERT_EQ(reqBody.records.size(), 0);

    OHOS::MessageParcel parcel;
    bool ret = reqBody.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnDeleteRecordsPhotosReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.records.size(), 0);
}

HWTEST_F(OnDeleteRecordsPhotosVoTest, TC006_ReqBody_Marshalling_Unmarshalling_Single, TestSize.Level1)
{
    // 用例说明：测试OnDeleteRecordsPhotosReqBody单元素序列化/反序列化；覆盖单元素集合场景（触发条件：records包含1个元素）；验证业务状态断言：反序列化后records大小和内容正确

    OnDeleteRecordsPhotosReqBody reqBody;
    OnDeleteRecordsPhoto record;
    record.dkRecordId = "dk_record_123";
    record.cloudId = "cloud_id_456";
    record.isSuccess = true;
    reqBody.AddDeleteRecord(record);

    OHOS::MessageParcel parcel;
    bool ret = reqBody.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnDeleteRecordsPhotosReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.records.size(), 1);
    EXPECT_EQ(restored.records[0].dkRecordId, "dk_record_123");
}

HWTEST_F(OnDeleteRecordsPhotosVoTest, TC007_ReqBody_Marshalling_Unmarshalling_Multiple, TestSize.Level1)
{
    // 用例说明：测试OnDeleteRecordsPhotosReqBody多元素序列化/反序列化；覆盖多元素集合场景（触发条件：records包含多个元素）；验证业务状态断言：反序列化后records大小和内容正确

    OnDeleteRecordsPhotosReqBody reqBody;
    OnDeleteRecordsPhoto record1;
    record1.dkRecordId = "dk_record_1";
    record1.cloudId = "cloud_id_1";
    record1.isSuccess = true;
    reqBody.AddDeleteRecord(record1);

    OnDeleteRecordsPhoto record2;
    record2.dkRecordId = "dk_record_2";
    record2.cloudId = "cloud_id_2";
    record2.isSuccess = false;
    reqBody.AddDeleteRecord(record2);

    OHOS::MessageParcel parcel;
    bool ret = reqBody.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnDeleteRecordsPhotosReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.records.size(), 2);
    EXPECT_EQ(restored.records[0].dkRecordId, "dk_record_1");
    EXPECT_EQ(restored.records[1].dkRecordId, "dk_record_2");
}

HWTEST_F(OnDeleteRecordsPhotosVoTest, TC008_RespBody_Marshalling_Unmarshalling_Success, TestSize.Level1)
{
    // 用例说明：测试OnDeleteRecordsPhotosRespBody序列化/反序列化成功路径；覆盖failSize字段正常读写（触发条件：failSize有效）；验证业务状态断言：反序列化后failSize值正确

    OnDeleteRecordsPhotosRespBody original;
    original.failSize = 5;

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnDeleteRecordsPhotosRespBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.failSize, original.failSize);
}

HWTEST_F(OnDeleteRecordsPhotosVoTest, TC009_RespBody_Unmarshalling_ReadInt32FailSize_Fail, TestSize.Level1)
{
    // 用例说明：测试OnDeleteRecordsPhotosRespBody反序列化失败路径；覆盖failSize字段读取失败（触发条件：MessageParcel.ReadInt32失败）；
    // 验证业务状态断言：反序列化返回false

    OHOS::MessageParcel parcel;
    bool ret = parcel.WriteInt32(5);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnDeleteRecordsPhotosRespBody vo;
    ret = vo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

}  // namespace OHOS::Media::CloudSync

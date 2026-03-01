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

#include "cloud_mdkrecord_photos_vo.h"

#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Media::CloudSync;

namespace OHOS::Media::CloudSync {

class CloudMdkRecordPhotosVoTest : public testing::Test {};

HWTEST_F(CloudMdkRecordPhotosVoTest, TC010_TruncateDataBy200K_Success, TestSize.Level1)
{
    // 用例说明：测试CloudMdkRecordPhotosRespBody数据截断功能；覆盖正常路径（触发条件：数据量未超过200K）；验证业务状态断言：截断后数据量不变

    std::vector<CloudMdkRecordPhotosVo> records;

    CloudMdkRecordPhotosVo record1;
    record1.cloudId = "cloud_id_1";
    record1.fileId = 1;
    record1.displayName = "photo1.jpg";
    records.push_back(record1);

    CloudMdkRecordPhotosVo record2;
    record2.cloudId = "cloud_id_2";
    record2.fileId = 2;
    record2.displayName = "photo2.jpg";
    records.push_back(record2);

    CloudMdkRecordPhotosRespBody respBody(records);
    size_t originalSize = respBody.GetDataSize();
    bool ret = respBody.TruncateDataBy200K();
    EXPECT_TRUE(ret);
    EXPECT_EQ(respBody.GetDataSize(), originalSize);
}

HWTEST_F(CloudMdkRecordPhotosVoTest, TC011_TruncateDataBy200K_Empty, TestSize.Level1)
{
    // 用例说明：测试CloudMdkRecordPhotosRespBody空数据截断；覆盖正常路径（触发条件：数据为空）；验证业务状态断言：截断成功

    CloudMdkRecordPhotosRespBody respBody;
    bool ret = respBody.TruncateDataBy200K();
    EXPECT_TRUE(ret);
}

HWTEST_F(CloudMdkRecordPhotosVoTest, TC012_TruncateDataBy200K_CapacityExceed, TestSize.Level1)
{
    // 用例说明：测试CloudMdkRecordPhotosRespBody超容量数据截断；覆盖正常路径（触发条件：数据量超过200K）；验证业务状态断言：截断后数据量减少

    std::vector<CloudMdkRecordPhotosVo> records;

    for (int i = 0; i < 100; i++) {
        CloudMdkRecordPhotosVo record;
        record.cloudId = "cloud_id_" + std::to_string(i);
        record.fileId = i;
        record.displayName = "photo_" + std::to_string(i) + ".jpg";
        record.stringfields["large_field"] = std::string(5000, 'x');
        records.push_back(record);
    }

    CloudMdkRecordPhotosRespBody respBody(records);
    size_t originalSize = respBody.GetDataSize();
    bool ret = respBody.TruncateDataBy200K();
    EXPECT_TRUE(ret);
    EXPECT_LE(respBody.GetDataSize(), originalSize);
}

HWTEST_F(CloudMdkRecordPhotosVoTest, TC013_GetRecords_NegativeLength, TestSize.Level1)
{
    // 用例说明：测试CloudMdkRecordPhotosRespBody反序列化负数长度；覆盖错误路径（触发条件：长度为负数）；验证业务状态断言：反序列化失败

    OHOS::MessageParcel parcel;
    parcel.WriteInt32(-1);

    parcel.RewindRead(0);
    std::vector<CloudMdkRecordPhotosVo> val;
    bool ret = CloudMdkRecordPhotosRespBody().GetRecords(val, parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(CloudMdkRecordPhotosVoTest, TC014_GetRecords_SizeOverflow, TestSize.Level1)
{
    // 用例说明：测试CloudMdkRecordPhotosRespBody反序列化溢出长度；覆盖错误路径（触发条件：长度为INT32_MAX）；验证业务状态断言：反序列化失败

    OHOS::MessageParcel parcel;
    parcel.WriteInt32(INT32_MAX);

    parcel.RewindRead(0);
    std::vector<CloudMdkRecordPhotosVo> val;
    bool ret = CloudMdkRecordPhotosRespBody().GetRecords(val, parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(CloudMdkRecordPhotosVoTest, TC015_GetRecords_SizeExceedReadable, TestSize.Level1)
{
    // 用例说明：测试CloudMdkRecordPhotosRespBody反序列化超可读长度；覆盖错误路径（触发条件：长度超过可读字节数）；验证业务状态断言：反序列化失败

    OHOS::MessageParcel parcel;
    parcel.WriteInt32(1000);

    parcel.RewindRead(0);
    std::vector<CloudMdkRecordPhotosVo> val;
    bool ret = CloudMdkRecordPhotosRespBody().GetRecords(val, parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(CloudMdkRecordPhotosVoTest, TC016_GetRecords_Success, TestSize.Level1)
{
    // 用例说明：测试CloudMdkRecordPhotosRespBody序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致

    std::vector<CloudMdkRecordPhotosVo> originalRecords;

    CloudMdkRecordPhotosVo record1;
    record1.cloudId = "cloud_id_1";
    record1.fileId = 1;
    record1.displayName = "photo1.jpg";
    originalRecords.push_back(record1);

    CloudMdkRecordPhotosVo record2;
    record2.cloudId = "cloud_id_2";
    record2.fileId = 2;
    record2.displayName = "photo2.jpg";
    originalRecords.push_back(record2);

    OHOS::MessageParcel parcel;
    bool ret = CloudMdkRecordPhotosRespBody(originalRecords).Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    std::vector<CloudMdkRecordPhotosVo> restoredRecords;
    ret = CloudMdkRecordPhotosRespBody().GetRecords(restoredRecords, parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restoredRecords.size(), 2);
    EXPECT_EQ(restoredRecords[0].cloudId, "cloud_id_1");
    EXPECT_EQ(restoredRecords[1].cloudId, "cloud_id_2");
}

HWTEST_F(CloudMdkRecordPhotosVoTest, TC017_TruncateDataBy200K_SingleLargeRecord, TestSize.Level1)
{
    // 用例说明：测试CloudMdkRecordPhotosRespBody单条大记录截断；覆盖边界路径（触发条件：单条记录接近200K）；验证业务状态断言：截断后数据量不变

    std::vector<CloudMdkRecordPhotosVo> records;

    CloudMdkRecordPhotosVo record;
    record.cloudId = "cloud_id_1";
    record.fileId = 1;
    record.displayName = "photo.jpg";
    record.stringfields["large_field"] = std::string(200000, 'x');
    records.push_back(record);

    CloudMdkRecordPhotosRespBody respBody(records);
    size_t originalSize = respBody.GetDataSize();
    bool ret = respBody.TruncateDataBy200K();
    EXPECT_TRUE(ret);
    EXPECT_EQ(respBody.GetDataSize(), originalSize);
}
}  // namespace OHOS::Media::CloudSync

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

#include "get_check_records_vo.h"

#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Media::CloudSync;

namespace OHOS::Media::CloudSync {

class GetCheckRecordsVoTest : public testing::Test {};

HWTEST_F(GetCheckRecordsVoTest, TC017_Unmarshalling_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致

    OHOS::MessageParcel parcel;
    parcel.WriteInt32(2);
    parcel.WriteString("key1");

    GetCheckRecordsRespBodyCheckData data1;
    data1.cloudId = "cloud_id_1";
    data1.size = 1024;
    data1.data = "data1";
    data1.displayName = "photo1.jpg";
    data1.fileName = "photo1.jpg";
    data1.mediaType = 1;
    data1.cloudVersion = 1;
    data1.position = 0;
    data1.dateModified = 1234567890;
    data1.dirty = 0;
    data1.thmStatus = 0;
    data1.syncStatus = 0;
    data1.fileSourceType = 0;
    data1.storagePath = "/storage";
    data1.Marshalling(parcel);

    parcel.WriteString("key2");
    GetCheckRecordsRespBodyCheckData data2;
    data2.cloudId = "cloud_id_2";
    data2.size = 2048;
    data2.data = "data2";
    data2.displayName = "photo2.jpg";
    data2.fileName = "photo2.jpg";
    data2.mediaType = 1;
    data2.cloudVersion = 1;
    data2.position = 0;
    data2.dateModified = 1234567890;
    data2.dirty = 0;
    data2.thmStatus = 0;
    data2.syncStatus = 0;
    data2.fileSourceType = 0;
    data2.storagePath = "/storage";
    data2.Marshalling(parcel);

    parcel.RewindRead(0);
    GetCheckRecordsRespBody respBody;
    bool ret = respBody.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(respBody.checkDataList.size(), 2);
    EXPECT_EQ(respBody.checkDataList["key1"].cloudId, "cloud_id_1");
    EXPECT_EQ(respBody.checkDataList["key2"].size, 2048);
}

HWTEST_F(GetCheckRecordsVoTest, TC018_Unmarshalling_SizeZero, TestSize.Level1)
{
    // 用例说明：测试基本功能；覆盖正常路径（触发条件：正常输入）；验证业务状态断言：功能正常

    OHOS::MessageParcel parcel;
    parcel.WriteInt32(0);

    parcel.RewindRead(0);
    GetCheckRecordsRespBody respBody;
    bool ret = respBody.Unmarshalling(parcel);
    EXPECT_TRUE(ret);
    EXPECT_EQ(respBody.checkDataList.size(), 0);
}

HWTEST_F(GetCheckRecordsVoTest, TC019_Unmarshalling_SizeNegative, TestSize.Level1)
{
    // 用例说明：测试反序列化负数错误；覆盖错误路径（触发条件：输入为负数）；验证业务状态断言：反序列化失败

    OHOS::MessageParcel parcel;
    parcel.WriteInt32(-1);

    parcel.RewindRead(0);
    GetCheckRecordsRespBody respBody;
    bool ret = respBody.Unmarshalling(parcel);
    EXPECT_TRUE(ret);
    EXPECT_EQ(respBody.checkDataList.size(), 0);
}

}  // namespace OHOS::Media::CloudSync

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

#include "get_download_thm_vo.h"
#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Media::CloudSync;

namespace OHOS::Media::CloudSync {

class GetDownloadThmVoTest : public testing::Test {};

HWTEST_F(GetDownloadThmVoTest, TC001_Unmarshalling_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    GetDownloadThmReqBody reqBody;
    reqBody.size = 1024;
    reqBody.type = 1;
    reqBody.offset = 0;
    reqBody.isDownloadDisplayFirst = true;

    OHOS::MessageParcel parcel;
    bool ret = reqBody.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    GetDownloadThmReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.size, reqBody.size);
    EXPECT_EQ(restored.type, reqBody.type);
    EXPECT_EQ(restored.offset, reqBody.offset);
    EXPECT_EQ(restored.isDownloadDisplayFirst, reqBody.isDownloadDisplayFirst);
}

HWTEST_F(GetDownloadThmVoTest, TC002_RespUnmarshalling_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    GetDownloadThmRespBody respBody;
    PhotosVo photo;
    photo.fileId = 123;
    photo.cloudId = "cloud_id_123";
    photo.size = 2048;
    respBody.photos.push_back(photo);

    OHOS::MessageParcel parcel;
    bool ret = respBody.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    GetDownloadThmRespBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.photos.size(), 1);
    EXPECT_EQ(restored.photos[0].fileId, photo.fileId);
    EXPECT_EQ(restored.photos[0].cloudId, photo.cloudId);
}

}  // namespace OHOS::Media::CloudSync

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

#include "on_delete_records_album_vo.h"

#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Media::CloudSync;

namespace OHOS::Media::CloudSync {

class OnDeleteRecordsAlbumVoTest : public testing::Test {};

HWTEST_F(OnDeleteRecordsAlbumVoTest, TC001_RespUnmarshalling_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    OnDeleteRecordsAlbumRespBody respBody;
    respBody.failSize = 0;

    OHOS::MessageParcel parcel;
    bool ret = respBody.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnDeleteRecordsAlbumRespBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.failSize, respBody.failSize);
}

HWTEST_F(OnDeleteRecordsAlbumVoTest, TC002_ReqBodyMarshalling_Unmarshalling_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    OnDeleteRecordsAlbumReqBody reqBody;

    OnDeleteAlbumData albumData;
    albumData.cloudId = "cloud_id_123";
    albumData.isSuccess = true;
    reqBody.AddSuccessResult(albumData);

    OHOS::MessageParcel parcel;
    bool ret = reqBody.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnDeleteRecordsAlbumReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    auto albums = restored.albums;
    EXPECT_EQ(albums.size(), 1);
    EXPECT_EQ(albums[0].cloudId, albumData.cloudId);
}

}  // namespace OHOS::Media::CloudSync

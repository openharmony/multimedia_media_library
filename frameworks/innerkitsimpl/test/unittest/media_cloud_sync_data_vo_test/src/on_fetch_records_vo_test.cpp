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

#include "on_fetch_records_vo.h"

#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing;
using namespace testing::ext;

namespace OHOS::Media::CloudSync {

class OnFetchRecordsVoTest : public testing::Test {};

HWTEST_F(OnFetchRecordsVoTest, TC007_SplitBy20K_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致

    OnFetchRecordsReqBody reqBody;

    OnFetchPhotosVo photo1;
    photo1.cloudId = "cloud_id_1";
    photo1.fileName = "photo1.jpg";
    photo1.fileId = 1;
    reqBody.AddOnFetchPhotoData(photo1);

    OnFetchPhotosVo photo2;
    photo2.cloudId = "cloud_id_2";
    photo2.fileName = "photo2.jpg";
    photo2.fileId = 2;
    reqBody.AddOnFetchPhotoData(photo2);

    std::vector<OnFetchRecordsReqBody> reqBodyList;
    bool ret = reqBody.SplitBy20K(reqBodyList);
    ASSERT_TRUE(ret);

    size_t totalRecords = 0;
    for (auto &body : reqBodyList) {
        totalRecords += body.GetOnFetchPhotoData().size();
    }
    EXPECT_EQ(totalRecords, 2);
    EXPECT_EQ(reqBodyList.size(), 1u);
}

HWTEST_F(OnFetchRecordsVoTest, TC015_SplitBy20K_Empty, TestSize.Level1)
{
    // 用例说明：测试空数据处理；覆盖边界路径（触发条件：输入为空）；验证业务状态断言：处理成功或失败

    OnFetchRecordsReqBody reqBody;
    std::vector<OnFetchRecordsReqBody> reqBodyList;
    bool ret = reqBody.SplitBy20K(reqBodyList);
    EXPECT_TRUE(ret);
    EXPECT_EQ(reqBodyList.size(), 0);
}

HWTEST_F(OnFetchRecordsVoTest, TC016_SplitBy20K_CapacityExceed, TestSize.Level1)
{
    // 用例说明：测试基本功能；覆盖正常路径（触发条件：正常输入）；验证业务状态断言：功能正常

    OnFetchRecordsReqBody reqBody;

    for (int i = 0; i < 100; i++) {
        OnFetchPhotosVo photo;
        photo.cloudId = "cloud_id_" + std::to_string(i);
        photo.fileName = "photo_" + std::to_string(i) + ".jpg";
        photo.fileId = i;
        photo.stringfields["large_field"] = std::string(5000, 'x');
        reqBody.AddOnFetchPhotoData(photo);
    }

    std::vector<OnFetchRecordsReqBody> reqBodyList;
    bool ret = reqBody.SplitBy20K(reqBodyList);
    ASSERT_TRUE(ret);

    size_t totalRecords = 0;
    for (auto &body : reqBodyList) {
        totalRecords += body.GetOnFetchPhotoData().size();
    }
    EXPECT_EQ(totalRecords, 100);
    EXPECT_GT(reqBodyList.size(), 1u);
}

HWTEST_F(OnFetchRecordsVoTest, TC027_MergeRespBody_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致

    OnFetchRecordsRespBody respBody1;
    respBody1.failedRecords.push_back("failed_id_1");
    respBody1.newDatas.resize(2);
    respBody1.fdirtyDatas.resize(1);
    respBody1.stats.resize(5);
    respBody1.stats[0] = 10;

    OnFetchRecordsRespBody respBody2;
    respBody2.failedRecords.push_back("failed_id_2");
    respBody2.newDatas.resize(3);
    respBody2.fdirtyDatas.resize(2);
    respBody2.stats.resize(5);
    respBody2.stats[0] = 5;

    respBody1.MergeRespBody(respBody2);

    EXPECT_EQ(respBody1.failedRecords.size(), 2);
    EXPECT_EQ(respBody1.newDatas.size(), 5);
    EXPECT_EQ(respBody1.fdirtyDatas.size(), 3);
    EXPECT_EQ(respBody1.stats[0], 15);
}

}  // namespace OHOS::Media::CloudSync

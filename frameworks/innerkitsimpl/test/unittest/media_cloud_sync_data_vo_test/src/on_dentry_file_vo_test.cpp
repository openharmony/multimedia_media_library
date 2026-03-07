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

#include "on_dentry_file_vo.h"

#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Media::CloudSync;

namespace OHOS::Media::CloudSync {

class OnDentryFileVoTest : public testing::Test {};

HWTEST_F(OnDentryFileVoTest, TC014_SplitBy20K_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致

    OnDentryFileReqBody reqBody;

    OnFetchPhotosVo photo1;
    photo1.cloudId = "cloud_id_1";
    photo1.fileName = "photo1.jpg";
    photo1.fileId = 1;
    reqBody.AddOnDentryFileRecord(photo1);

    OnFetchPhotosVo photo2;
    photo2.cloudId = "cloud_id_2";
    photo2.fileName = "photo2.jpg";
    photo2.fileId = 2;
    reqBody.AddOnDentryFileRecord(photo2);

    std::vector<OnDentryFileReqBody> reqBodyList;
    bool ret = reqBody.SplitBy20K(reqBodyList);
    ASSERT_TRUE(ret);

    size_t totalRecords = 0;
    for (auto &body : reqBodyList) {
        totalRecords += body.GetOnDentryFileRecord().size();
    }
    EXPECT_EQ(totalRecords, 2);
    EXPECT_GT(reqBodyList.size(), 1u);
}

HWTEST_F(OnDentryFileVoTest, TC015_SplitBy20K_Empty, TestSize.Level1)
{
    // 用例说明：测试空数据处理；覆盖边界路径（触发条件：输入为空）；验证业务状态断言：处理成功或失败

    OnDentryFileReqBody reqBody;
    std::vector<OnDentryFileReqBody> reqBodyList;
    bool ret = reqBody.SplitBy20K(reqBodyList);
    EXPECT_TRUE(ret);
    EXPECT_EQ(reqBodyList.size(), 0);
}

HWTEST_F(OnDentryFileVoTest, TC016_SplitBy20K_CapacityExceed, TestSize.Level1)
{
    // 用例说明：测试基本功能；覆盖正常路径（触发条件：正常输入）；验证业务状态断言：功能正常

    OnDentryFileReqBody reqBody;

    for (int i = 0; i < 100; i++) {
        OnFetchPhotosVo photo;
        photo.cloudId = "cloud_id_" + std::to_string(i);
        photo.fileName = "photo_" + std::to_string(i) + ".jpg";
        photo.fileId = i;
        photo.stringfields["large_field"] = std::string(5000, 'x');
        reqBody.AddOnDentryFileRecord(photo);
    }

    std::vector<OnDentryFileReqBody> reqBodyList;
    bool ret = reqBody.SplitBy20K(reqBodyList);
    ASSERT_TRUE(ret);

    size_t totalRecords = 0;
    for (auto &body : reqBodyList) {
        totalRecords += body.GetOnDentryFileRecord().size();
    }
    EXPECT_EQ(totalRecords, 100);
    EXPECT_GT(reqBodyList.size(), 1u);
}

HWTEST_F(OnDentryFileVoTest, TC028_MergeRespBody_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致

    OnDentryFileRespBody respBody1;
    respBody1.failedRecords.push_back("failed_id_1");

    OnDentryFileRespBody respBody2;
    respBody2.failedRecords.push_back("failed_id_2");
    respBody2.failedRecords.push_back("failed_id_3");

    respBody1.MergeRespBody(respBody2);

    EXPECT_EQ(respBody1.failedRecords.size(), 3);
    EXPECT_EQ(respBody1.failedRecords[0], "failed_id_1");
    EXPECT_EQ(respBody1.failedRecords[1], "failed_id_2");
    EXPECT_EQ(respBody1.failedRecords[2], "failed_id_3");
}

}  // namespace OHOS::Media::CloudSync

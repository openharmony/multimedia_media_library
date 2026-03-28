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

#include "on_download_asset_vo.h"

#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Media::CloudSync;

namespace OHOS::Media::CloudSync {

class OnDownloadAssetVoTest : public testing::Test {};

HWTEST_F(OnDownloadAssetVoTest, TC001_Marshalling_Unmarshalling_Empty_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    OnDownloadAssetReqBody original;
    original.cloudIds.clear();
    original.downloadedFileInfos.clear();

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnDownloadAssetReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.cloudIds.size(), 0);
}

HWTEST_F(OnDownloadAssetVoTest, TC002_Marshalling_Unmarshalling_SingleCloudId_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    OnDownloadAssetReqBody original;
    original.cloudIds.push_back("cloud_id_001");
    original.downloadedFileInfos.clear();

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnDownloadAssetReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.cloudIds.size(), 1);
    EXPECT_EQ(restored.cloudIds[0], "cloud_id_001");
}

HWTEST_F(OnDownloadAssetVoTest, TC003_Marshalling_Unmarshalling_MultipleCloudIds_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    OnDownloadAssetReqBody original;
    original.cloudIds.push_back("cloud_id_001");
    original.cloudIds.push_back("cloud_id_002");
    original.cloudIds.push_back("cloud_id_003");
    original.downloadedFileInfos.clear();

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnDownloadAssetReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.cloudIds.size(), 3);
    EXPECT_EQ(restored.cloudIds[0], "cloud_id_001");
    EXPECT_EQ(restored.cloudIds[1], "cloud_id_002");
    EXPECT_EQ(restored.cloudIds[2], "cloud_id_003");
}

HWTEST_F(OnDownloadAssetVoTest, TC004_Marshalling_Unmarshalling_WithLakeInfo_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    OnDownloadAssetReqBody original;
    original.cloudIds.push_back("cloud_id_001");

    AdditionFileInfo lakeInfo;
    lakeInfo.isUpdate = true;
    lakeInfo.fileSourceType = 1;
    lakeInfo.storagePath = "/storage/test/path";
    lakeInfo.title = "test_title";
    lakeInfo.displayName = "test_display_name";
    original.downloadedFileInfos["cloud_id_001"] = lakeInfo;

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnDownloadAssetReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.cloudIds.size(), 1);
    EXPECT_EQ(restored.cloudIds[0], "cloud_id_001");
}

HWTEST_F(OnDownloadAssetVoTest, TC005_Marshalling_Unmarshalling_MultipleLakeInfos_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    OnDownloadAssetReqBody original;
    original.cloudIds.push_back("cloud_id_001");
    original.cloudIds.push_back("cloud_id_002");

    AdditionFileInfo lakeInfo1;
    lakeInfo1.isUpdate = true;
    lakeInfo1.fileSourceType = 1;
    lakeInfo1.storagePath = "/storage/test/path1";
    lakeInfo1.title = "test_title1";
    lakeInfo1.displayName = "test_display_name1";
    original.downloadedFileInfos["cloud_id_001"] = lakeInfo1;

    AdditionFileInfo lakeInfo2;
    lakeInfo2.isUpdate = false;
    lakeInfo2.fileSourceType = 2;
    lakeInfo2.storagePath = "/storage/test/path2";
    lakeInfo2.title = "test_title2";
    lakeInfo2.displayName = "test_display_name2";
    original.downloadedFileInfos["cloud_id_002"] = lakeInfo2;

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnDownloadAssetReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.cloudIds.size(), 2);
}

HWTEST_F(OnDownloadAssetVoTest, TC006_Marshalling_Unmarshalling_SpecialStrings_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    OnDownloadAssetReqBody original;
    original.cloudIds.push_back("");
    original.cloudIds.push_back("cloud_id_with_中文");
    original.cloudIds.push_back("cloud_id_with_special!@#$%^&*()");
    original.downloadedFileInfos.clear();

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnDownloadAssetReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.cloudIds.size(), 3);
    EXPECT_EQ(restored.cloudIds[0], "");
    EXPECT_EQ(restored.cloudIds[1], "cloud_id_with_中文");
    EXPECT_EQ(restored.cloudIds[2], "cloud_id_with_special!@#$%^&*()");
}

HWTEST_F(OnDownloadAssetVoTest, TC010_Marshalling_Unmarshalling_LargeVector_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    OnDownloadAssetReqBody original;
    for (int i = 0; i < 100; i++) {
        original.cloudIds.push_back("cloud_id_" + std::to_string(i));
    }
    original.downloadedFileInfos.clear();

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnDownloadAssetReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.cloudIds.size(), 100);
    for (int i = 0; i < 100; i++) {
        EXPECT_EQ(restored.cloudIds[i], "cloud_id_" + std::to_string(i));
    }
}

HWTEST_F(OnDownloadAssetVoTest, TC011_Marshalling_Unmarshalling_LongString_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    OnDownloadAssetReqBody original;
    std::string longCloudId(1000, 'A');
    original.cloudIds.push_back(longCloudId);
    original.downloadedFileInfos.clear();

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnDownloadAssetReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.cloudIds.size(), 1);
    EXPECT_EQ(restored.cloudIds[0], longCloudId);
}

}  // namespace OHOS::Media::CloudSync

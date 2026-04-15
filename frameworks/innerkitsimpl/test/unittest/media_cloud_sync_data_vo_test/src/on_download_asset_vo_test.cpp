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
    original.downloadedFileInfos.clear();

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnDownloadAssetReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.downloadedFileInfos.size(), 0);
}

HWTEST_F(OnDownloadAssetVoTest, TC002_Marshalling_Unmarshalling_SingleFileInfo_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    OnDownloadAssetReqBody original;

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

    EXPECT_EQ(restored.downloadedFileInfos.size(), 1);
    EXPECT_EQ(restored.downloadedFileInfos["cloud_id_001"].storagePath, "/storage/test/path");
}

HWTEST_F(OnDownloadAssetVoTest, TC003_Marshalling_Unmarshalling_MultipleFileInfos_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    OnDownloadAssetReqBody original;

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

    AdditionFileInfo lakeInfo3;
    lakeInfo3.isUpdate = true;
    lakeInfo3.fileSourceType = 3;
    lakeInfo3.storagePath = "/storage/test/path3";
    lakeInfo3.title = "test_title3";
    lakeInfo3.displayName = "test_display_name3";
    original.downloadedFileInfos["cloud_id_003"] = lakeInfo3;

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnDownloadAssetReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.downloadedFileInfos.size(), 3);
    EXPECT_EQ(restored.downloadedFileInfos["cloud_id_001"].storagePath, "/storage/test/path1");
    EXPECT_EQ(restored.downloadedFileInfos["cloud_id_002"].storagePath, "/storage/test/path2");
    EXPECT_EQ(restored.downloadedFileInfos["cloud_id_003"].storagePath, "/storage/test/path3");
}

HWTEST_F(OnDownloadAssetVoTest, TC004_Marshalling_Unmarshalling_WithLakeInfo_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    OnDownloadAssetReqBody original;

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

    EXPECT_EQ(restored.downloadedFileInfos.size(), 1);
    EXPECT_EQ(restored.downloadedFileInfos["cloud_id_001"].storagePath, "/storage/test/path");
}

HWTEST_F(OnDownloadAssetVoTest, TC005_Marshalling_Unmarshalling_MultipleLakeInfos_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    OnDownloadAssetReqBody original;

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

    EXPECT_EQ(restored.downloadedFileInfos.size(), 2);
    EXPECT_EQ(restored.downloadedFileInfos["cloud_id_001"].storagePath, "/storage/test/path1");
    EXPECT_EQ(restored.downloadedFileInfos["cloud_id_002"].storagePath, "/storage/test/path2");
}

HWTEST_F(OnDownloadAssetVoTest, TC006_Marshalling_Unmarshalling_SpecialStrings_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    OnDownloadAssetReqBody original;

    AdditionFileInfo lakeInfo1;
    lakeInfo1.isUpdate = true;
    lakeInfo1.fileSourceType = 1;
    lakeInfo1.storagePath = "";
    lakeInfo1.title = "test_title";
    lakeInfo1.displayName = "test_display_name";
    original.downloadedFileInfos[""] = lakeInfo1;

    AdditionFileInfo lakeInfo2;
    lakeInfo2.isUpdate = false;
    lakeInfo2.fileSourceType = 2;
    lakeInfo2.storagePath = "/storage/test/path_中文";
    lakeInfo2.title = "test_title";
    lakeInfo2.displayName = "test_display_name";
    original.downloadedFileInfos["cloud_id_with_中文"] = lakeInfo2;

    AdditionFileInfo lakeInfo3;
    lakeInfo3.isUpdate = true;
    lakeInfo3.fileSourceType = 3;
    lakeInfo3.storagePath = "/storage/test/path!@#$%^&*()";
    lakeInfo3.title = "test_title";
    lakeInfo3.displayName = "test_display_name";
    original.downloadedFileInfos["cloud_id_with_special!@#$%^&*()"] = lakeInfo3;

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnDownloadAssetReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.downloadedFileInfos.size(), 3);
    EXPECT_EQ(restored.downloadedFileInfos[""].storagePath, "");
    EXPECT_EQ(restored.downloadedFileInfos["cloud_id_with_中文"].storagePath, "/storage/test/path_中文");
    EXPECT_EQ(restored.downloadedFileInfos["cloud_id_with_special!@#$%^&*()"].storagePath,
              "/storage/test/path!@#$%^&*()");
}

HWTEST_F(OnDownloadAssetVoTest, TC010_Marshalling_Unmarshalling_LargeVector_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    OnDownloadAssetReqBody original;
    for (int i = 0; i < 100; i++) {
        AdditionFileInfo lakeInfo;
        lakeInfo.isUpdate = (i % 2 == 0);
        lakeInfo.fileSourceType = i;
        lakeInfo.storagePath = "/storage/test/path_" + std::to_string(i);
        lakeInfo.title = "test_title_" + std::to_string(i);
        lakeInfo.displayName = "test_display_name_" + std::to_string(i);
        original.downloadedFileInfos["cloud_id_" + std::to_string(i)] = lakeInfo;
    }

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnDownloadAssetReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.downloadedFileInfos.size(), 100);
    for (int i = 0; i < 100; i++) {
        std::string cloudId = "cloud_id_" + std::to_string(i);
        EXPECT_EQ(restored.downloadedFileInfos[cloudId].storagePath, "/storage/test/path_" + std::to_string(i));
        EXPECT_EQ(restored.downloadedFileInfos[cloudId].title, "test_title_" + std::to_string(i));
    }
}

HWTEST_F(OnDownloadAssetVoTest, TC011_Marshalling_Unmarshalling_LongString_Success, TestSize.Level1)
{
    // 用例说明：测试序列化与反序列化；覆盖正常路径（触发条件：正常数据）；验证业务状态断言：反序列化后的数据与原始数据一致
    OnDownloadAssetReqBody original;
    std::string longCloudId(1000, 'A');
    std::string longStoragePath(1000, 'B');

    AdditionFileInfo lakeInfo;
    lakeInfo.isUpdate = true;
    lakeInfo.fileSourceType = 1;
    lakeInfo.storagePath = longStoragePath;
    lakeInfo.title = "test_title";
    lakeInfo.displayName = "test_display_name";
    original.downloadedFileInfos[longCloudId] = lakeInfo;

    OHOS::MessageParcel parcel;
    bool ret = original.Marshalling(parcel);
    ASSERT_TRUE(ret);

    parcel.RewindRead(0);
    OnDownloadAssetReqBody restored;
    ret = restored.Unmarshalling(parcel);
    ASSERT_TRUE(ret);

    EXPECT_EQ(restored.downloadedFileInfos.size(), 1);
    EXPECT_EQ(restored.downloadedFileInfos[longCloudId].storagePath, longStoragePath);
}

}  // namespace OHOS::Media::CloudSync

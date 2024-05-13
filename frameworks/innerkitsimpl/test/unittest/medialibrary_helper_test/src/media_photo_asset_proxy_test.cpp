/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "media_photo_asset_proxy_test.h"

#include "iservice_registry.h"
#include "media_log.h"
#include "medialibrary_errno.h"

#define private public
#include "media_photo_asset_proxy.h"
#undef private

#include "mock_photo_proxy_test.h"
#include "system_ability_definition.h"
#include "userfilemgr_uri.h"

using namespace std;
using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace Media {
constexpr int STORAGE_MANAGER_MANAGER_ID = 5003;

shared_ptr<PhotoAssetProxy> photoAssetProxy;

std::shared_ptr<DataShare::DataShareHelper> sDataShareHelper_ = nullptr;

void CreateDataHelper(int32_t systemAbilityId);

void MediaPhotoAssetProxyUnitTest::SetUpTestCase(void)
{
    CreateDataHelper(STORAGE_MANAGER_MANAGER_ID);
}

void MediaPhotoAssetProxyUnitTest::TearDownTestCase(void) {}

void MediaPhotoAssetProxyUnitTest::SetUp(void)
{
    photoAssetProxy = make_shared<PhotoAssetProxy>();
}

void MediaPhotoAssetProxyUnitTest::TearDown(void) {}

void CreateDataHelper(int32_t systemAbilityId)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        MEDIA_ERR_LOG("Get system ability mgr failed.");
        return;
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    if (remoteObj == nullptr) {
        MEDIA_ERR_LOG("GetSystemAbility Service Failed.");
        return;
    }

    if (sDataShareHelper_ == nullptr) {
        const sptr<IRemoteObject> &token = remoteObj;
        sDataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    }
}

HWTEST_F(MediaPhotoAssetProxyUnitTest, MediaPhotoAssetProxy_CreatePhotoAsset_DataShareHelper_null_001, TestSize.Level0)
{
    photoAssetProxy->dataShareHelper_ = nullptr;
    shared_ptr<PhotoProxyTest> photoProxyTest = make_shared<PhotoProxyTest>();

    shared_ptr<MockPhotoProxyTest> mockPhotoProxy = make_shared<MockPhotoProxyTest>();
    EXPECT_CALL(*mockPhotoProxy.get(), GetDisplayName()).Times(Exactly(0));

    photoAssetProxy->CreatePhotoAsset((sptr<PhotoProxy>&)photoProxyTest);
}

HWTEST_F(MediaPhotoAssetProxyUnitTest, MediaPhotoAssetProxy_CreatePhotoAsset_displayName_empty_002, TestSize.Level0)
{
    photoAssetProxy->dataShareHelper_ = sDataShareHelper_;

    shared_ptr<PhotoProxyTest> photoProxyTest = make_shared<PhotoProxyTest>();
    shared_ptr<MockPhotoProxyTest> mockPhotoProxy = make_shared<MockPhotoProxyTest>();
    EXPECT_CALL(*mockPhotoProxy.get(), GetDisplayName()).WillOnce(Return(""));

    photoAssetProxy->CreatePhotoAsset((sptr<PhotoProxy>&)mockPhotoProxy);
}

HWTEST_F(MediaPhotoAssetProxyUnitTest, MediaPhotoAssetProxy_CreatePhotoAsset_invalid_media_type_003, TestSize.Level0)
{
    photoAssetProxy->dataShareHelper_ = sDataShareHelper_;

    shared_ptr<PhotoProxyTest> photoProxyTest = make_shared<PhotoProxyTest>();
    shared_ptr<MockPhotoProxyTest> mockPhotoProxy = make_shared<MockPhotoProxyTest>();
    EXPECT_CALL(*mockPhotoProxy.get(), GetDisplayName()).Times(2).WillRepeatedly(Return("IMG_20240512_153621.tmp"));

    photoAssetProxy->CreatePhotoAsset((sptr<PhotoProxy>&)mockPhotoProxy);
}

HWTEST_F(MediaPhotoAssetProxyUnitTest, MediaPhotoAssetProxy_CreatePhotoAsset_invalid_media_type_004, TestSize.Level0)
{
    photoAssetProxy->dataShareHelper_ = sDataShareHelper_;

    shared_ptr<PhotoProxyTest> photoProxyTest = make_shared<PhotoProxyTest>();
    shared_ptr<MockPhotoProxyTest> mockPhotoProxy = make_shared<MockPhotoProxyTest>();
    EXPECT_CALL(*mockPhotoProxy.get(), GetDisplayName()).Times(3).WillRepeatedly(Return("IMG_20240512_153621.jpg"));

    photoAssetProxy->CreatePhotoAsset((sptr<PhotoProxy>&)mockPhotoProxy);
}

HWTEST_F(MediaPhotoAssetProxyUnitTest, MediaPhotoAssetProxy_GetFileAsset_invalid_dataShareHelper_001, TestSize.Level0)
{
    photoAssetProxy->dataShareHelper_ = nullptr;
    EXPECT_EQ(photoAssetProxy->GetFileAsset(), nullptr);
}

HWTEST_F(MediaPhotoAssetProxyUnitTest, MediaPhotoAssetProxy_GetFileAsset_asset_not_exist_002, TestSize.Level0)
{
    photoAssetProxy->dataShareHelper_ = sDataShareHelper_;
    EXPECT_EQ(photoAssetProxy->GetFileAsset(), nullptr);
}

HWTEST_F(MediaPhotoAssetProxyUnitTest, MediaPhotoAssetProxy_GetFileAsset_ok_003, TestSize.Level0)
{
    photoAssetProxy->dataShareHelper_ = sDataShareHelper_;
    shared_ptr<PhotoProxyTest> photoProxyTest = make_shared<PhotoProxyTest>();
    shared_ptr<MockPhotoProxyTest> mockPhotoProxy = make_shared<MockPhotoProxyTest>();
    EXPECT_CALL(*mockPhotoProxy.get(), GetDisplayName()).Times(3).WillRepeatedly(Return("IMG_20240512_153621.jpg"));

    photoAssetProxy->CreatePhotoAsset((sptr<PhotoProxy>&)mockPhotoProxy);
    EXPECT_NE(photoAssetProxy->GetFileAsset(), nullptr);
}
}
}
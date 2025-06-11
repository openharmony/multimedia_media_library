/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "media_notification_register_manager_test.h"
#include "media_datashare_stub_impl.h"

#include "media_log.h"
#include "medialibrary_errno.h"
#include "get_self_permissions.h"
#include "media_change_info.h"

using namespace testing::ext;
using namespace OHOS::AbilityRuntime;
using namespace OHOS::AAFwk;

namespace OHOS {
namespace Media {
void NotificationRegisterManagerTest::SetUpTestCase(void)
{
    std::vector<string> perms;
    MEDIA_INFO_LOG("NotificationRegisterManagerTest start");
    perms.push_back("ohos.permission.READ_IMAGEVIDEO");
    perms.push_back("ohos.permission.WRITE_IMAGEVIDEO");
    uint64_t tokenId = -1;
    PermissionUtilsUnitTest::SetAccessTokenPermission("NotificationRegisterManagerTest", perms, tokenId);
    ASSERT_TRUE(tokenId != 0);
    MEDIA_INFO_LOG("NotificationRegisterManagerTest end");
}

void NotificationRegisterManagerTest::TearDownTestCase(void)
{
}

void NotificationRegisterManagerTest::SetUp(void)
{
}

void NotificationRegisterManagerTest::TearDown(void)
{
    MEDIA_INFO_LOG("NotificationRegisterManagerTest TearDown start");
    auto observerManager = Notification::MediaObserverManager::GetObserverManager();
    observerManager->observers_.clear();
    observerManager->obsCallbackPecipients_.clear();
    MEDIA_INFO_LOG("NotificationRegisterManagerTest TearDown end");
}

HWTEST_F(NotificationRegisterManagerTest, NotificationRegisterManager_test_001, TestSize.Level1) {
    // 1个uri,1个observer
    MEDIA_INFO_LOG("NotificationRegisterManager_test_001::Start");
    Notification::NotifyUriType uri = Notification::NotifyUriType::PHOTO_URI;
    auto observerManager = Notification::MediaObserverManager::GetObserverManager();
    EXPECT_NE(observerManager, nullptr);
    sptr<IDataAbilityObserver> dataObserver = new (std::nothrow) IDataAbilityObserverTest();
    EXPECT_NE(dataObserver, nullptr);

    int32_t ret = observerManager->AddObserver(uri, dataObserver);
    EXPECT_EQ(ret, E_OK);
    size_t uriSize = observerManager->observers_.size();
    EXPECT_EQ(uriSize, 1);
    size_t observerSize = observerManager->FindObserver(uri).size();
    EXPECT_EQ(observerSize, 1);
    size_t obsCallbackSize = observerManager->obsCallbackPecipients_.size();
    EXPECT_EQ(obsCallbackSize, 1);
    observerManager->RemoveObserver(dataObserver->AsObject());
    uriSize = observerManager->observers_.size();
    EXPECT_EQ(uriSize, 0);
    obsCallbackSize = observerManager->obsCallbackPecipients_.size();
    EXPECT_EQ(obsCallbackSize, 0);
    MEDIA_INFO_LOG("NotificationRegisterManager_test_001::End");
}

HWTEST_F(NotificationRegisterManagerTest, NotificationRegisterManager_test_002, TestSize.Level1) {
    // 1个uri,1个observer
    MEDIA_INFO_LOG("NotificationRegisterManager_test_002::Start");
    Notification::NotifyUriType uri = Notification::NotifyUriType::PHOTO_ALBUM_URI;
    auto observerManager = Notification::MediaObserverManager::GetObserverManager();
    EXPECT_NE(observerManager, nullptr);
    sptr<IDataAbilityObserver> dataObserver = new (std::nothrow) IDataAbilityObserverTest();
    EXPECT_NE(dataObserver, nullptr);

    int32_t ret = observerManager->AddObserver(uri, dataObserver);
    EXPECT_EQ(ret, E_OK);
    size_t uriSize = observerManager->observers_.size();
    EXPECT_EQ(uriSize, 1);
    size_t observerSize = observerManager->FindObserver(uri).size();
    size_t obsCallbackSize = observerManager->obsCallbackPecipients_.size();
    EXPECT_EQ(observerSize, 1);
    EXPECT_EQ(obsCallbackSize, 1);
    observerManager->RemoveObserver(dataObserver->AsObject());
    uriSize = observerManager->observers_.size();
    EXPECT_EQ(uriSize, 0);
    obsCallbackSize = observerManager->obsCallbackPecipients_.size();
    EXPECT_EQ(obsCallbackSize, 0);
    MEDIA_INFO_LOG("NotificationRegisterManager_test_002::End");
}

HWTEST_F(NotificationRegisterManagerTest, NotificationRegisterManager_test_003, TestSize.Level1) {
    // 1个uri ，2个observer
    MEDIA_INFO_LOG("NotificationRegisterManager_test_003::Start");
    Notification::NotifyUriType uri = Notification::NotifyUriType::PHOTO_URI;
    auto observerManager = Notification::MediaObserverManager::GetObserverManager();
    EXPECT_NE(observerManager, nullptr);
    sptr<IDataAbilityObserver> dataObserver = new (std::nothrow) IDataAbilityObserverTest();
    EXPECT_NE(dataObserver, nullptr);
    sptr<IDataAbilityObserver> secondDataObserver = new (std::nothrow) IDataAbilityObserverTest();
    EXPECT_NE(secondDataObserver, nullptr);

    int32_t ret = observerManager->AddObserver(uri, dataObserver);
    EXPECT_EQ(ret, E_OK);
    ret = observerManager->AddObserver(uri, secondDataObserver);
    EXPECT_EQ(ret, E_OK);
    size_t uriSize = observerManager->observers_.size();
    EXPECT_EQ(uriSize, 1);
    size_t observerSize = observerManager->FindObserver(uri).size();
    EXPECT_EQ(observerSize, 2);
    size_t obsCallbackSize = observerManager->obsCallbackPecipients_.size();
    EXPECT_EQ(obsCallbackSize, 2);

    observerManager->RemoveObserver(dataObserver->AsObject());
    uriSize = observerManager->observers_.size();
    EXPECT_EQ(uriSize, 1);
    obsCallbackSize = observerManager->obsCallbackPecipients_.size();
    EXPECT_EQ(obsCallbackSize, 1);
    observerManager->RemoveObserver(secondDataObserver->AsObject());
    uriSize = observerManager->observers_.size();
    EXPECT_EQ(uriSize, 0);
    obsCallbackSize = observerManager->obsCallbackPecipients_.size();
    EXPECT_EQ(obsCallbackSize, 0);
    MEDIA_INFO_LOG("NotificationRegisterManager_test_003::End");
}

HWTEST_F(NotificationRegisterManagerTest, NotificationRegisterManager_test_004, TestSize.Level1) {
    // 1个uri ，2个observer
    MEDIA_INFO_LOG("NotificationRegisterManager_test_004::Start");
    Notification::NotifyUriType uri = Notification::NotifyUriType::PHOTO_ALBUM_URI;
    auto observerManager = Notification::MediaObserverManager::GetObserverManager();
    EXPECT_NE(observerManager, nullptr);
    sptr<IDataAbilityObserver> dataObserver = new (std::nothrow) IDataAbilityObserverTest();
    EXPECT_NE(dataObserver, nullptr);
    sptr<IDataAbilityObserver> secondDataObserver = new (std::nothrow) IDataAbilityObserverTest();
    EXPECT_NE(secondDataObserver, nullptr);

    int32_t ret = observerManager->AddObserver(uri, dataObserver);
    EXPECT_EQ(ret, E_OK);
    ret = observerManager->AddObserver(uri, secondDataObserver);
    EXPECT_EQ(ret, E_OK);
    size_t uriSize = observerManager->observers_.size();
    EXPECT_EQ(uriSize, 1);
    size_t observerSize = observerManager->FindObserver(uri).size();
    EXPECT_EQ(observerSize, 2);
    size_t obsCallbackSize = observerManager->obsCallbackPecipients_.size();
    EXPECT_EQ(obsCallbackSize, 2);

    observerManager->RemoveObserver(dataObserver->AsObject());
    uriSize = observerManager->observers_.size();
    EXPECT_EQ(uriSize, 1);
    obsCallbackSize = observerManager->obsCallbackPecipients_.size();
    EXPECT_EQ(obsCallbackSize, 1);
    observerManager->RemoveObserver(secondDataObserver->AsObject());
    uriSize = observerManager->observers_.size();
    EXPECT_EQ(uriSize, 0);
    obsCallbackSize = observerManager->obsCallbackPecipients_.size();
    EXPECT_EQ(obsCallbackSize, 0);
    MEDIA_INFO_LOG("NotificationRegisterManager_test_004::End");
}

HWTEST_F(NotificationRegisterManagerTest, NotificationRegisterManager_test_005, TestSize.Level1) {
    // 2个uri ，1个observer
    MEDIA_INFO_LOG("NotificationRegisterManager_test_005::Start");
    Notification::NotifyUriType photoUri = Notification::NotifyUriType::PHOTO_URI;
    Notification::NotifyUriType albumUri = Notification::NotifyUriType::PHOTO_ALBUM_URI;

    auto observerManager = Notification::MediaObserverManager::GetObserverManager();
    EXPECT_NE(observerManager, nullptr);
    sptr<IDataAbilityObserver> dataObserver = new (std::nothrow) IDataAbilityObserverTest();
    EXPECT_NE(dataObserver, nullptr);

    int32_t ret = observerManager->AddObserver(photoUri, dataObserver);
    EXPECT_EQ(ret, E_OK);
    ret = observerManager->AddObserver(albumUri, dataObserver);
    EXPECT_EQ(ret, E_OK);
    size_t uriSize = observerManager->observers_.size();
    EXPECT_EQ(uriSize, 2);
    size_t obsCallbackSize = observerManager->obsCallbackPecipients_.size();
    EXPECT_EQ(obsCallbackSize, 1);
    size_t observerSize = observerManager->observers_.at(photoUri).size();
    EXPECT_EQ(observerSize, 1);
    observerSize = observerManager->observers_.at(albumUri).size();
    EXPECT_EQ(observerSize, 1);

    observerManager->RemoveObserver(dataObserver->AsObject());
    uriSize = observerManager->observers_.size();
    EXPECT_EQ(uriSize, 0);
    obsCallbackSize = observerManager->obsCallbackPecipients_.size();
    EXPECT_EQ(obsCallbackSize, 0);
    MEDIA_INFO_LOG("NotificationRegisterManager_test_005::End");
}

HWTEST_F(NotificationRegisterManagerTest, NotificationRegisterManager_test_006, TestSize.Level1) {
    // 2个uri ，2个observer
    MEDIA_INFO_LOG("NotificationRegisterManager_test_006::Start");
    Notification::NotifyUriType photoUri = Notification::NotifyUriType::PHOTO_URI;
    Notification::NotifyUriType albumUri = Notification::NotifyUriType::PHOTO_ALBUM_URI;

    auto observerManager = Notification::MediaObserverManager::GetObserverManager();
    EXPECT_NE(observerManager, nullptr);
    sptr<IDataAbilityObserver> dataObserver = new (std::nothrow) IDataAbilityObserverTest();
    EXPECT_NE(dataObserver, nullptr);
    sptr<IDataAbilityObserver> secondDataObserver = new (std::nothrow) IDataAbilityObserverTest();
    EXPECT_NE(secondDataObserver, nullptr);

    int32_t ret = observerManager->AddObserver(photoUri, dataObserver);
    EXPECT_EQ(ret, E_OK);
    ret = observerManager->AddObserver(albumUri, secondDataObserver);
    EXPECT_EQ(ret, E_OK);
    size_t uriSize = observerManager->observers_.size();
    EXPECT_EQ(uriSize, 2);
    size_t obsCallbackSize = observerManager->obsCallbackPecipients_.size();
    EXPECT_EQ(obsCallbackSize, 2);
    size_t observerSize = observerManager->observers_.at(photoUri).size();
    EXPECT_EQ(observerSize, 1);
    observerSize = observerManager->observers_.at(albumUri).size();
    EXPECT_EQ(observerSize, 1);

    observerManager->RemoveObserver(dataObserver->AsObject());
    uriSize = observerManager->observers_.size();
    EXPECT_EQ(uriSize, 1);
    obsCallbackSize = observerManager->obsCallbackPecipients_.size();
    EXPECT_EQ(obsCallbackSize, 1);
    observerManager->RemoveObserver(secondDataObserver->AsObject());
    uriSize = observerManager->observers_.size();
    EXPECT_EQ(uriSize, 0);
    obsCallbackSize = observerManager->obsCallbackPecipients_.size();
    EXPECT_EQ(obsCallbackSize, 0);
    MEDIA_INFO_LOG("NotificationRegisterManager_test_006::End");
}

HWTEST_F(NotificationRegisterManagerTest, NotificationRegisterManager_test_007, TestSize.Level1) {
    // 1个uri,1个observer
    MEDIA_INFO_LOG("NotificationRegisterManager_test_007::Start");
    Notification::NotifyUriType uri = Notification::NotifyUriType::PHOTO_URI;
    auto observerManager = Notification::MediaObserverManager::GetObserverManager();
    EXPECT_NE(observerManager, nullptr);
    sptr<IDataAbilityObserver> dataObserver = new (std::nothrow) IDataAbilityObserverTest();
    EXPECT_NE(dataObserver, nullptr);

    int32_t ret = observerManager->AddObserver(uri, dataObserver);
    EXPECT_EQ(ret, E_OK);
    size_t uriSize = observerManager->observers_.size();
    EXPECT_EQ(uriSize, 1);
    size_t observerSize = observerManager->FindObserver(uri).size();
    EXPECT_EQ(observerSize, 1);
    size_t obsCallbackSize = observerManager->obsCallbackPecipients_.size();
    EXPECT_EQ(obsCallbackSize, 1);
    ret = observerManager->AddObserver(uri, dataObserver);
    EXPECT_EQ(ret, E_DATAOBSERVER_IS_REPEATED);

    observerManager->RemoveObserver(dataObserver->AsObject());
    uriSize = observerManager->observers_.size();
    EXPECT_EQ(uriSize, 0);
    obsCallbackSize = observerManager->obsCallbackPecipients_.size();
    EXPECT_EQ(obsCallbackSize, 0);
    MEDIA_INFO_LOG("NotificationRegisterManager_test_007::End");
}
}
}
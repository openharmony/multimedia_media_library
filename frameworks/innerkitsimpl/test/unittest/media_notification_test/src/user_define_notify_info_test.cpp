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
 
#define MLOG_TAG "UserDefineNotifyInfoTest"
 
#include "user_define_notify_info_test.h"
 
#include "multistages_capture_notify_info.h"
#include "user_define_notify_info.h"
 
#include <string>
#include <unordered_set>
 
using namespace std;
using namespace OHOS;
using namespace testing::ext;
 
namespace OHOS {
namespace Media {
using namespace Notification;
void UserDefineNotifyInfoTest::SetUpTestCase(void) {}
 
void UserDefineNotifyInfoTest::TearDownTestCase(void) {}
 
void UserDefineNotifyInfoTest::SetUp() {}
 
void UserDefineNotifyInfoTest::TearDown(void) {}
 
/**
 * @tc.name: medialib_SetUserDefineNotifyBody_test01
 * @tc.desc: UserDefineNotifyInfo 可设置body
 */
HWTEST_F(UserDefineNotifyInfoTest, medialib_SetUserDefineNotifyBody_test01, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_SetUserDefineNotifyBody_test01");
    UserDefineNotifyInfo notifyInfo(
        NotifyUriType::USER_DEFINE_NOTIFY_URI, NotifyForUserDefineType::MULTISTAGES_CAPTURE);
    EXPECT_EQ(notifyInfo.readOnly_, false);

    auto notifyBody = std::make_shared<NotifyBodyTest>();
    EXPECT_NE(notifyBody, nullptr);

    notifyInfo.SetUserDefineNotifyBody(notifyBody);
    EXPECT_EQ(notifyInfo.readOnly_, true);
    EXPECT_NE(notifyInfo.notifyBody_, nullptr);
    MEDIA_INFO_LOG("end medialib_SetUserDefineNotifyBody_test01");
}
 
/**
 * @tc.name: medialib_SetUserDefineNotifyBody_test02
 * @tc.desc: UserDefineNotifyInfo 的 body 不可设置为空指针
 */
HWTEST_F(UserDefineNotifyInfoTest, medialib_SetUserDefineNotifyBody_test02, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_SetUserDefineNotifyBody_test02");
    UserDefineNotifyInfo notifyInfo(
        NotifyUriType::USER_DEFINE_NOTIFY_URI, NotifyForUserDefineType::MULTISTAGES_CAPTURE);
    EXPECT_EQ(notifyInfo.readOnly_, false);
    EXPECT_EQ(notifyInfo.notifyBody_, nullptr);

    notifyInfo.SetUserDefineNotifyBody(nullptr);
    EXPECT_EQ(notifyInfo.readOnly_, false);
    EXPECT_EQ(notifyInfo.notifyBody_, nullptr);
    MEDIA_INFO_LOG("end medialib_SetUserDefineNotifyBody_test02");
}
 
/**
 * @tc.name: medialib_SetUserDefineNotifyBody_test03
 * @tc.desc: UserDefineNotifyInfo 的 body 只读状态下不可重复设置
 */
HWTEST_F(UserDefineNotifyInfoTest, medialib_SetUserDefineNotifyBody_test03, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_SetUserDefineNotifyBody_test03");
    UserDefineNotifyInfo notifyInfo(
        NotifyUriType::USER_DEFINE_NOTIFY_URI, NotifyForUserDefineType::MULTISTAGES_CAPTURE);
    EXPECT_EQ(notifyInfo.readOnly_, false);
    EXPECT_EQ(notifyInfo.notifyBody_, nullptr);
 
    auto notifyBody = std::make_shared<NotifyBodyTest>();
    EXPECT_NE(notifyBody, nullptr);
    notifyInfo.readOnly_ = true;
    notifyInfo.SetUserDefineNotifyBody(notifyBody);
    EXPECT_EQ(notifyInfo.readOnly_, false);
    EXPECT_EQ(notifyInfo.notifyBody_, nullptr);
    MEDIA_INFO_LOG("end medialib_SetUserDefineNotifyBody_test03");
}
 
/**
 * @tc.name: medialib_GetUserDefineNotifyBody_test01
 * @tc.desc: UserDefineNotifyInfo 的 body 只能在只读状态下，可以读取
 */
HWTEST_F(UserDefineNotifyInfoTest, medialib_GetUserDefineNotifyBody_test01, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_GetUserDefineNotifyBody_test01");
    UserDefineNotifyInfo notifyInfo(
        NotifyUriType::USER_DEFINE_NOTIFY_URI, NotifyForUserDefineType::MULTISTAGES_CAPTURE);
    EXPECT_EQ(notifyInfo.readOnly_, false);
 
    auto notifyBody = notifyInfo.GetUserDefineNotifyBody();
    EXPECT_EQ(notifyBody, nullptr);
 
    auto notifyBodyInput = std::make_shared<NotifyBodyTest>();
    EXPECT_NE(notifyBodyInput, nullptr);
 
    notifyInfo.SetUserDefineNotifyBody(notifyBodyInput);
    EXPECT_EQ(notifyInfo.readOnly_, true);
    EXPECT_NE(notifyInfo.notifyBody_, nullptr);
 
    notifyBody = notifyInfo.GetUserDefineNotifyBody();
    EXPECT_NE(notifyBody, nullptr);
    MEDIA_INFO_LOG("end medialib_GetUserDefineNotifyBody_test01");
}
 
/**
 * @tc.name: medialib_WriteHeadFromParcel_test01
 * @tc.desc: UserDefineNotifyInfo 的 notifyUri_ 不满足，则不允许被序列化
 */
HWTEST_F(UserDefineNotifyInfoTest, medialib_WriteHeadFromParcel_test01, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_WriteHeadFromParcel_test01");
    UserDefineNotifyInfo notifyInfo(NotifyUriType::PHOTO_URI, NotifyForUserDefineType::MULTISTAGES_CAPTURE);
 
    std::shared_ptr<Parcel> parcel = std::make_shared<Parcel>();
    EXPECT_NE(parcel, nullptr);
    bool ret = notifyInfo.WriteHeadFromParcel(parcel);
    EXPECT_EQ(ret, false);
    MEDIA_INFO_LOG("end medialib_WriteHeadFromParcel_test01");
}
 
/**
 * @tc.name: medialib_WriteHeadFromParcel_test02
 * @tc.desc: UserDefineNotifyInfo 的 notifyUserDefineType_ 不满足，则不允许被序列化
 */
HWTEST_F(UserDefineNotifyInfoTest, medialib_WriteHeadFromParcel_test02, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_WriteHeadFromParcel_test02");
    UserDefineNotifyInfo notifyInfo(
        NotifyUriType::USER_DEFINE_NOTIFY_URI, NotifyForUserDefineType::UNDEFINED);
 
    std::shared_ptr<Parcel> parcel = std::make_shared<Parcel>();
    EXPECT_NE(parcel, nullptr);
    bool ret = notifyInfo.WriteHeadFromParcel(parcel);
    EXPECT_EQ(ret, false);
    MEDIA_INFO_LOG("end medialib_WriteHeadFromParcel_test02");
}
 
/**
 * @tc.name: medialib_WriteHeadFromParcel_test03
 * @tc.desc: UserDefineNotifyInfo 的 notifyUri_ && notifyUserDefineType_ 均满足，才可以被序列化
 */
HWTEST_F(UserDefineNotifyInfoTest, medialib_WriteHeadFromParcel_test03, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_WriteHeadFromParcel_test03");
    UserDefineNotifyInfo notifyInfo(
        NotifyUriType::USER_DEFINE_NOTIFY_URI, NotifyForUserDefineType::MULTISTAGES_CAPTURE);
 
    std::shared_ptr<Parcel> parcel = std::make_shared<Parcel>();
    EXPECT_NE(parcel, nullptr);
    bool ret = notifyInfo.WriteHeadFromParcel(parcel);
    EXPECT_EQ(ret, true);
    MEDIA_INFO_LOG("end medialib_WriteHeadFromParcel_test03");
}
 
/**
 * @tc.name: medialib_ReadHeadFromParcel_test01
 * @tc.desc: UserDefineNotifyInfo 的 notifyUri_ 只能是 USER_DEFINE_NOTIFY_URI, 不允许反序列化。
 */
HWTEST_F(UserDefineNotifyInfoTest, medialib_ReadHeadFromParcel_test01, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_ReadHeadFromParcel_test01");
    std::shared_ptr<Parcel> parcel = std::make_shared<Parcel>();
    parcel->WriteUint16(static_cast<uint16_t>(NotifyUriType::PHOTO_URI));
    parcel->WriteUint16(static_cast<uint16_t>(NotifyForUserDefineType::UNDEFINED));
 
    UserDefineNotifyInfo* info = new (std::nothrow)UserDefineNotifyInfo();
    EXPECT_NE(info, nullptr);
    bool ret = info->ReadHeadFromParcel(*parcel);
    EXPECT_EQ(ret, false);
    MEDIA_INFO_LOG("end medialib_ReadHeadFromParcel_test01");
}
 
/**
 * @tc.name: medialib_ReadHeadFromParcel_test02
 * @tc.desc: UserDefineNotifyInfo 的 notifyUserDefineType_ 不能是 UNDEFINED，不允许反序列化。
 */
HWTEST_F(UserDefineNotifyInfoTest, medialib_ReadHeadFromParcel_test02, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_ReadHeadFromParcel_test02");
    std::shared_ptr<Parcel> parcel = std::make_shared<Parcel>();
    parcel->WriteUint16(static_cast<uint16_t>(NotifyUriType::USER_DEFINE_NOTIFY_URI));
    parcel->WriteUint16(static_cast<uint16_t>(NotifyForUserDefineType::UNDEFINED));
 
    UserDefineNotifyInfo* info = new (std::nothrow)UserDefineNotifyInfo();
    EXPECT_NE(info, nullptr);
    bool ret = info->ReadHeadFromParcel(*parcel);
    EXPECT_EQ(ret, false);
    MEDIA_INFO_LOG("end medialib_ReadHeadFromParcel_test02");
}
 
/**
 * @tc.name: medialib_ReadHeadFromParcel_test03
 * @tc.desc: UserDefineNotifyInfo 的 notifyUri_ && notifyUserDefineType_ 均满足，才可以被反序列化
 */
HWTEST_F(UserDefineNotifyInfoTest, medialib_ReadHeadFromParcel_test03, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_ReadHeadFromParcel_test03");
    std::shared_ptr<Parcel> parcel = std::make_shared<Parcel>();
    parcel->WriteUint16(static_cast<uint16_t>(NotifyUriType::USER_DEFINE_NOTIFY_URI));
    parcel->WriteUint16(static_cast<uint16_t>(NotifyForUserDefineType::UNDEFINED));
 
    UserDefineNotifyInfo* info = new (std::nothrow)UserDefineNotifyInfo();
    EXPECT_NE(info, nullptr);
    bool ret = info->ReadHeadFromParcel(*parcel);
    EXPECT_EQ(ret, false);
    MEDIA_INFO_LOG("end medialib_ReadHeadFromParcel_test03");
}
 
/**
 * @tc.name: medialib_WriteBodyFromParcel_test01
 * @tc.desc: UserDefineNotifyInfo 的 body 只能在只读状态下，才允许被序列化
 */
HWTEST_F(UserDefineNotifyInfoTest, medialib_WriteBodyFromParcel_test01, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_WriteBodyFromParcel_test01");
    UserDefineNotifyInfo notifyInfo(
        NotifyUriType::USER_DEFINE_NOTIFY_URI, NotifyForUserDefineType::MULTISTAGES_CAPTURE);
    EXPECT_EQ(notifyInfo.readOnly_, false);
 
    std::shared_ptr<Parcel> parcel = std::make_shared<Parcel>();
    bool ret = notifyInfo.WriteBodyFromParcel(parcel);
    EXPECT_EQ(ret, false);
 
    auto notifyBody = std::make_shared<NotifyBodyTest>();
    EXPECT_NE(notifyBody, nullptr);
 
    notifyInfo.SetUserDefineNotifyBody(notifyBody);
    EXPECT_EQ(notifyInfo.readOnly_, true);
    EXPECT_NE(notifyInfo.notifyBody_, nullptr);
 
    ret = notifyInfo.WriteBodyFromParcel(parcel);
    EXPECT_EQ(ret, true);
    MEDIA_INFO_LOG("end medialib_WriteBodyFromParcel_test01");
}
 
/**
 * @tc.name: medialib_ReadBodyFromParcel_test01
 * @tc.desc: UserDefineNotifyInfo 需要定义body类型，才允许被反序列化
 */
HWTEST_F(UserDefineNotifyInfoTest, medialib_ReadBodyFromParcel_test01, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_ReadBodyFromParcel_test01");
    UserDefineNotifyInfo notifyInfo(
        NotifyUriType::USER_DEFINE_NOTIFY_URI, NotifyForUserDefineType::MULTISTAGES_CAPTURE);
    EXPECT_EQ(notifyInfo.readOnly_, false);
 
    std::shared_ptr<Parcel> parcel = std::make_shared<Parcel>();
    notifyInfo.WriteHeadFromParcel(parcel);
 
    auto notifyBody = std::make_shared<NotifyBodyTest>();
    EXPECT_NE(notifyBody, nullptr);
 
    notifyInfo.SetUserDefineNotifyBody(notifyBody);
    EXPECT_EQ(notifyInfo.readOnly_, true);
 
    UserDefineNotifyInfo* info = new (std::nothrow)UserDefineNotifyInfo();
    bool ret = info->ReadHeadFromParcel(*parcel);
    EXPECT_EQ(ret, true);
 
    info->notifyUserDefineType_ = NotifyForUserDefineType::UNDEFINED;
    ret = info->ReadBodyFromParcel(*parcel);
    EXPECT_EQ(ret, false);
    MEDIA_INFO_LOG("end medialib_ReadBodyFromParcel_test01");
}
 
/**
 * @tc.name: medialib_ReadBodyFromParcel_test02
 * @tc.desc: UserDefineNotifyInfo 在非只读状态下，不允许被反序列化
 */
HWTEST_F(UserDefineNotifyInfoTest, medialib_ReadBodyFromParcel_test02, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_ReadBodyFromParcel_test02");
    UserDefineNotifyInfo notifyInfo(
        NotifyUriType::USER_DEFINE_NOTIFY_URI, NotifyForUserDefineType::MULTISTAGES_CAPTURE);
    EXPECT_EQ(notifyInfo.readOnly_, false);
 
    std::shared_ptr<Parcel> parcel = std::make_shared<Parcel>();
    notifyInfo.WriteHeadFromParcel(parcel);
 
    auto notifyBody = std::make_shared<NotifyBodyTest>();
    EXPECT_NE(notifyBody, nullptr);
 
    notifyInfo.SetUserDefineNotifyBody(notifyBody);
    EXPECT_EQ(notifyInfo.readOnly_, true);
    notifyInfo.readOnly_ = false;
    EXPECT_EQ(notifyInfo.readOnly_, false);
 
    UserDefineNotifyInfo* info = new (std::nothrow)UserDefineNotifyInfo();
    bool ret = info->ReadHeadFromParcel(*parcel);
    EXPECT_EQ(ret, true);
 
    ret = info->ReadBodyFromParcel(*parcel);
    EXPECT_EQ(notifyInfo.readOnly_, false);
    EXPECT_EQ(ret, false);
    MEDIA_INFO_LOG("end medialib_ReadBodyFromParcel_test02");
}
 
/**
 * @tc.name: medialib_ReadBodyFromParcel_test03
 * @tc.desc: UserDefineNotifyInfo 被反序列化
 */
HWTEST_F(UserDefineNotifyInfoTest, medialib_ReadBodyFromParcel_test03, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_ReadBodyFromParcel_test03");
    UserDefineNotifyInfo notifyInfo(
        NotifyUriType::USER_DEFINE_NOTIFY_URI, NotifyForUserDefineType::MULTISTAGES_CAPTURE);
    std::shared_ptr<Parcel> parcel = std::make_shared<Parcel>();
    notifyInfo.WriteHeadFromParcel(parcel);
 
    auto notifyBody = std::make_shared<NotifyBodyTest>();
    EXPECT_NE(notifyBody, nullptr);
    notifyInfo.SetUserDefineNotifyBody(notifyBody);
    EXPECT_EQ(notifyInfo.readOnly_, true);
 
    UserDefineNotifyInfo* info = new (std::nothrow)UserDefineNotifyInfo();
    bool ret = info->ReadHeadFromParcel(*parcel);
    EXPECT_EQ(ret, true);
    ret = info->ReadBodyFromParcel(*parcel);
    EXPECT_EQ(ret, true);
    MEDIA_INFO_LOG("end medialib_ReadBodyFromParcel_test03");
}
} // namespace Media
} // namespace OHOS
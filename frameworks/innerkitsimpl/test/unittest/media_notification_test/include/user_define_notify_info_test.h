/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
 
#ifndef MEDIALIBRARY_USER_DEFINE_NOTIFY_INFO_TEST_H
#define MEDIALIBRARY_USER_DEFINE_NOTIFY_INFO_TEST_H
 
#include <gtest/gtest.h>
 
#include "user_define_notify_info.h"
 
namespace OHOS {
namespace Media {
using namespace Notification;
class UserDefineNotifyInfoTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
 
class NotifyBodyTest final : public UserDefineNotifyBase {
public:
    bool Marshalling(Parcel &parcel) const override
    {
        return true;
    }
 
    bool UnMarshalling(Parcel &parcel) override
    {
        return true;
    }
 
    bool WriteToParcel(std::shared_ptr<Parcel> &parcel) override
    {
        return true;
    }
 
    std::string ToString() const override
    {
        return "";
    }
};
} // namespace Media
} // namespace OHOS
#endif  // MEDIALIBRARY_USER_DEFINE_NOTIFY_INFO_TEST_H
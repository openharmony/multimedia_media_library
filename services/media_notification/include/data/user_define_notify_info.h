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
 
#ifndef OHOS_MEDIA_USER_DEFINE_NOTIFY_INFO_H
#define OHOS_MEDIA_USER_DEFINE_NOTIFY_INFO_H
 
#include <string>
 
#include "media_change_info.h"
#include "parcel.h"
 
namespace OHOS {
namespace Media {
namespace Notification {
using namespace Media::AccurateRefresh;
 
enum class NotifyForUserDefineType {
    UNDEFINED = 0,
    MULTISTAGES_CAPTURE = 1,
    LOW_QUALITY_MEMORY = 2,
};
 
class EXPORT UserDefineNotifyBase : public Parcelable {
public:
    virtual bool UnMarshalling(Parcel &parcel) = 0;
    virtual bool WriteToParcel(std::shared_ptr<Parcel> &parcel) = 0;
    virtual std::string ToString() const = 0;
};
 
class EXPORT UserDefineNotifyInfo : public Parcelable {
public:
    UserDefineNotifyInfo() {}
    UserDefineNotifyInfo(const NotifyUriType &notifyUri, const NotifyForUserDefineType &notifyUserDefineType)
        : notifyUri_(notifyUri), notifyUserDefineType_(notifyUserDefineType) {}
    bool ReadHeadFromParcel(Parcel &parcel);
    bool WriteHeadFromParcel(std::shared_ptr<Parcel> &parcel) const;
    bool ReadBodyFromParcel(Parcel &parcel);
    bool WriteBodyFromParcel(std::shared_ptr<Parcel> &parcel) const;
    std::string ToString() const;
 
    void SetUserDefineNotifyBody(const std::shared_ptr<UserDefineNotifyBase> &notifyBody);
    std::shared_ptr<UserDefineNotifyBase> GetUserDefineNotifyBody() const;
 
    bool Marshalling(Parcel &parcel) const override
    {
        return true;
    }
 
public:
    NotifyUriType notifyUri_{NotifyUriType::USER_DEFINE_NOTIFY_URI};
    NotifyForUserDefineType notifyUserDefineType_{NotifyForUserDefineType::UNDEFINED};

private:
    std::shared_ptr<UserDefineNotifyBase> notifyBody_;
    bool readOnly_{false};
};
 
} // namespace Notification
} // namespace Media
} // namespace OHOS
#endif  // OHOS_MEDIA_USER_DEFINE_NOTIFY_INFO_H
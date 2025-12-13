/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
 
#ifndef OHOS_MEDIALIBRARY_MELTISTAGES_CAPTURE_NOTIFY_INFO_H
#define OHOS_MEDIALIBRARY_MELTISTAGES_CAPTURE_NOTIFY_INFO_H
 
#include <string>
#include <vector>
 
#include "camera_character_types.h"
#include "media_log.h"
#include "user_define_notify_info.h"
 
namespace OHOS {
namespace Media::Notification {
#define EXPORT __attribute__ ((visibility ("default")))
class MultistagesCaptureNotifyServerInfo final : public UserDefineNotifyBase {
public:
    bool Marshalling(Parcel &parcel) const override
    {
        return true;
    }
 
    bool UnMarshalling(Parcel &parcel) override
    {
        this->uri_ = parcel.ReadString();
        this->notifyType_ = static_cast<MultistagesCaptureNotifyType>(parcel.ReadUint32());
        return true;
    }
 
    bool WriteToParcel(std::shared_ptr<Parcel> &parcel) override
    {
        parcel->WriteString(this->uri_);
        parcel->WriteUint32(static_cast<uint32_t>(this->notifyType_));
        return true;
    }
 
    std::string ToString() const override
    {
        std::stringstream ss;
        ss << "{"
            << "\"uri\": \"" << this->uri_.c_str() << "\","
            << "\"notifyType\": \"" << std::to_string(static_cast<int32_t>(this->notifyType_))
            << "}";
        return ss.str();
    }
 
public:
    std::string uri_;
    MultistagesCaptureNotifyType notifyType_{MultistagesCaptureNotifyType::UNDEFINED};
};
} // namespace Media
} // namespace OHOS
#endif  // OHOS_MEDIALIBRARY_MELTISTAGES_CAPTURE_NOTIFY_INFO_H
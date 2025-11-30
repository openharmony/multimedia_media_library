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

#ifndef OHOS_LOW_QUALITY_MEMORY_NUM_NOTIFY_INFO_H
#define OHOS_LOW_QUALITY_MEMORY_NUM_NOTIFY_INFO_H

#include <string>
#include <vector>

#include "user_define_notify_info.h"

namespace OHOS {
namespace Media::Notification {
#define EXPORT __attribute__ ((visibility ("default")))
class LowQualityMemoryNumNotifyInfo final : public UserDefineNotifyBase {
public:
    bool Marshalling(Parcel &parcel) const override
    {
        return true;
    }
 
    bool UnMarshalling(Parcel &parcel) override
    {
        this->count_ = parcel.ReadInt32();
        return true;
    }
 
    bool WriteToParcel(std::shared_ptr<Parcel> &parcel) override
    {
        parcel->WriteInt32(this->count_);
        return true;
    }
 
    std::string ToString() const override
    {
        std::stringstream ss;
        ss << "{"
            << "\"count\": \"" << std::to_string(this->count_)
            << "}";
        return ss.str();
    }
 
public:
    int32_t count_{0};
};
} // namespace Media::Notification
} // namespace OHOS
#endif  // OHOS_LOW_QUALITY_MEMORY_NUM_NOTIFY_INFO_H
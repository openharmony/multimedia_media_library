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

#ifndef OHOS_MEDIA_IPC_MEDIA_REQ_VO_H
#define OHOS_MEDIA_IPC_MEDIA_REQ_VO_H

#include <string>
#include <sstream>

#include "parcel.h"

namespace OHOS::Media::IPC {
template <class T>
class MediaReqVo : public Parcelable {
private:
    std::string traceId;
    T body;

public:  // gettter and setter
    const std::string &GetTraceId() const
    {
        return this->traceId;
    }
    void SetTraceId(const std::string &traceId)
    {
        this->traceId = traceId;
        return;
    }
    T GetBody() const
    {
        return this->body;
    }
    void SetBody(T body)
    {
        this->body = body;
        return;
    }

public:  // functions of Parcelable.
    bool ReadFromParcel(Parcel &parcel)
    {
        parcel.ReadString(this->traceId);
        T *bodyPtrTmp = T::Unmarshalling(parcel);
        if (bodyPtrTmp != nullptr) {
            this->body = *bodyPtrTmp;
            delete bodyPtrTmp;
            bodyPtrTmp = nullptr;
        }
        return true;
    }

    bool Marshalling(Parcel &parcel) const override
    {
        parcel.WriteString(this->traceId);
        this->body.Marshalling(parcel);
        return true;
    }

    static MediaReqVo *Unmarshalling(Parcel &parcel)
    {
        MediaReqVo *info = new (std::nothrow) MediaReqVo();
        if ((info != nullptr) && (!info->ReadFromParcel(parcel))) {
            delete info;
            info = nullptr;
        }
        return info;
    }

public:  // basic functions
    std::string ToString() const
    {
        std::stringstream ss;
        ss << "{"
           << "\"traceId\": \"" << this->traceId << "\", "
           << "\"body\": " << this->body.ToString() << "}";
        return ss.str();
    }
};
}  // namespace OHOS::Media::IPC
#endif  // OHOS_MEDIA_IPC_MEDIA_REQ_VO_H
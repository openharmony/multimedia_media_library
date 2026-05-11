/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef MEDIA_PROGRESS_CHANGE_INFO_H
#define MEDIA_PROGRESS_CHANGE_INFO_H

#include <string>
#include <sstream>
#include "parcel.h"
#include "media_log.h"

namespace OHOS {
namespace Media {
namespace Notification {

// 进度回调类型枚举
enum ProgressCallbackType {
    PROGRESS_TYPE_UNKNOWN = 0,
    PROGRESS_TYPE_DOWNLOAD = 1,
    PROGRESS_TYPE_UPLOAD = 2,
    PROGRESS_TYPE_DELETE = 3,
    PROGRESS_TYPE_COPY = 4,
    PROGRESS_TYPE_MOVE = 5,
    PROGRESS_TYPE_TRANSCODE = 6,
    PROGRESS_TYPE_CANCEL = 7,
};

class MediaProgressChangeInfo : public Parcelable {
public:
    int32_t requestId{0};          // 请求ID
    int32_t type{0};               // 进度类型 (ProgressCallbackType)
    int64_t processedSize{0};            // 当前进度
    int64_t remainSize{0};                // 剩余数量
    int64_t processedCount{0};
    int64_t remainCount{0};
    int64_t totalCount{0};
    int64_t totalSize{0};              // 总进度
    int64_t realTimeprocessSize{0};

public:
    ~MediaProgressChangeInfo() override = default;

    std::string ToString() const
    {
        std::stringstream ss;
        ss << "MediaProgressChangeInfo{";
        ss << "requestId: " << requestId;
        ss << ", type: " << type;
        ss << ", processedSize: " << realTimeprocessSize;
        ss << ", remainSize: " << remainSize;
        ss << ", processedCount: " << processedCount;
        ss << ", remainCount: " << remainCount;
        ss << "}";
        return ss.str();
    }

    static std::shared_ptr<MediaProgressChangeInfo> Unmarshalling(Parcel &parcel)
    {
        MEDIA_DEBUG_LOG("MediaProgressChangeInfo::Unmarshalling");
        MediaProgressChangeInfo* info = new (std::nothrow) MediaProgressChangeInfo();
        if ((info != nullptr) && (!info->ReadFromParcel(parcel))) {
            delete info;
            info = nullptr;
        }
        return std::shared_ptr<MediaProgressChangeInfo>(info);
    }

    bool Marshalling(Parcel &parcel) const override
    {
        if (!parcel.WriteInt32(requestId)) {
            MEDIA_ERR_LOG("Failed to write requestId");
            return false;
        }
        if (!parcel.WriteInt32(type)) {
            MEDIA_ERR_LOG("Failed to write type");
            return false;
        }
        if (!parcel.WriteInt64(realTimeprocessSize)) {
            MEDIA_ERR_LOG("Failed to write processedSize");
            return false;
        }
        if (!parcel.WriteInt64(remainSize)) {
            MEDIA_ERR_LOG("Failed to write totalSize");
            return false;
        }
        if (!parcel.WriteInt64(processedCount)) {
            MEDIA_ERR_LOG("Failed to write processedSize");
            return false;
        }
        if (!parcel.WriteInt64(remainCount)) {
            MEDIA_ERR_LOG("Failed to write totalSize");
            return false;
        }
        return true;
    }

private:
    bool ReadFromParcel(Parcel &parcel)
    {
        requestId = parcel.ReadInt32();
        type = parcel.ReadInt32();
        realTimeprocessSize = parcel.ReadInt64();
        remainSize = parcel.ReadInt64();
        processedCount = parcel.ReadInt64();
        remainCount = parcel.ReadInt64();
        MEDIA_INFO_LOG("MediaProgressChangeInfo::ReadFromParcel success, %{public}s", ToString().c_str());
        return true;
    }
};

} // namespace Notification
} // namespace Media
} // namespace OHOS

#endif // MEDIA_PROGRESS_CHANGE_INFO_H
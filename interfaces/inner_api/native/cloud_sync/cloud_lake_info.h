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

#ifndef OHOS_MEDIA_CLOUD_LAKE_INFO_H
#define OHOS_MEDIA_CLOUD_LAKE_INFO_H

#include "message_parcel.h"

namespace OHOS::Media::CloudSync {
#define EXPORT __attribute__ ((visibility ("default")))

class EXPORT AdditionFileInfo {
public:
    operator bool() const { return isUpdate; }
    bool isUpdate{false};
    int32_t fileSourceType;
    std::string storagePath;
    std::string title;
    std::string displayName;

static bool Marshalling(const AdditionFileInfo &in, MessageParcel &p)
{
    return p.WriteBool(in.isUpdate) &&
           p.WriteInt32(in.fileSourceType) &&
           p.WriteString(in.storagePath) &&
           p.WriteString(in.title) &&
           p.WriteString(in.displayName);
}

static bool Unmarshalling(AdditionFileInfo &out, MessageParcel &p)
{
    return p.ReadBool(out.isUpdate) &&
           p.ReadInt32(out.fileSourceType) &&
           p.ReadString(out.storagePath) &&
           p.ReadString(out.title) &&
           p.ReadString(out.displayName);
}

static bool Marshalling(const std::unordered_map<std::string, AdditionFileInfo> &result, MessageParcel &parcel)
{
    if (!parcel.WriteInt32(static_cast<int32_t>(result.size()))) {
        return false;
    }
    for (const auto &entry : result) {
        if ((!parcel.WriteString(entry.first)) ||
            (!AdditionFileInfo::Marshalling(entry.second, parcel))) {
            return false;
        }
    }
    return true;
}

static bool Unmarshalling(std::unordered_map<std::string, AdditionFileInfo> &val, MessageParcel &parcel)
{
    int32_t size = 0;
    if (!parcel.ReadInt32(size)) {
        return false;
    }
    if (size < 0) {
        return false;
    }
    size_t readAbleSize = parcel.GetReadableBytes();
    if ((static_cast<size_t>(size) > readAbleSize) || static_cast<size_t>(size) > val.max_size()) {
        return false;
    }
    for (int32_t i = 0; i < size; i++) {
        std::string cloudId;
        if ((!parcel.ReadString(cloudId)) || (!Unmarshalling(val[cloudId], parcel))) {
            return false;
        }
    }
    return true;
}
};
} // namespace OHOS::Media::CloudSync

#endif // OHOS_MEDIA_CLOUD_SYNC_CLOUD_DL_FILE_META_H
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

#define MLOG_TAG "MediaFormInfoVo"

#include "form_info_vo.h"

#include <sstream>

#include "media_itypes_utils.h"
#include "media_log.h"

namespace OHOS::Media {
using namespace std;
bool FormInfoReqBody::Unmarshalling(MessageParcel &parcel)
{
    size_t size = static_cast<size_t>(parcel.ReadUint32());
    const char *buffer = reinterpret_cast<const char *>(parcel.ReadRawData(size));
    CHECK_AND_RETURN_RET_LOG(buffer, false, "ReadRawData failed, size: %{public}zu", size);

    std::istringstream iss(std::string(buffer, size), std::ios::binary);
    uint32_t idCount{0};
    CHECK_AND_RETURN_RET_LOG(iss.read(reinterpret_cast<char *>(&idCount), sizeof(idCount)),
        false,
        "read failed, idCount: %{public}u",
        idCount);
    formIds.reserve(idCount);
    for (uint32_t i = 0; i < idCount; ++i) {
        uint32_t len{0};
        CHECK_AND_RETURN_RET_LOG(
            iss.read(reinterpret_cast<char *>(&len), sizeof(len)), false, "read failed, len: %{public}u", len);
        std::string id(len, '\0');
        CHECK_AND_RETURN_RET_LOG(iss.read(&id[0], len), false, "read id failed, len: %{public}u", len);
        formIds.push_back(std::move(id));
    }

    uint32_t uriCount{0};
    CHECK_AND_RETURN_RET_LOG(iss.read(reinterpret_cast<char *>(&uriCount), sizeof(uriCount)),
        false,
        "read failed, uriCount: %{public}u",
        uriCount);
    fileUris.reserve(uriCount);
    for (uint32_t i = 0; i < uriCount; ++i) {
        uint32_t len{0};
        CHECK_AND_RETURN_RET_LOG(
            iss.read(reinterpret_cast<char *>(&len), sizeof(len)), false, "read failed, len: %{public}u", len);
        std::string uri(len, '\0');
        CHECK_AND_RETURN_RET_LOG(iss.read(&uri[0], len), false, "read uri failed, len: %{public}u", len);
        fileUris.push_back(std::move(uri));
    }

    return true;
}

bool FormInfoReqBody::Marshalling(MessageParcel &parcel) const
{
    std::ostringstream oss(std::ios::binary);
    uint32_t idCount = static_cast<uint32_t>(formIds.size());
    CHECK_AND_RETURN_RET_LOG(oss.write(reinterpret_cast<const char *>(&idCount), sizeof(idCount)),
        false,
        "write failed, idCount: %{public}u",
        idCount);
    for (const auto &id : formIds) {
        uint32_t len = static_cast<uint32_t>(id.size());
        CHECK_AND_RETURN_RET_LOG(
            oss.write(reinterpret_cast<const char *>(&len), sizeof(len)), false, "write failed, len: %{public}u", len);
        CHECK_AND_RETURN_RET_LOG(oss.write(id.data(), len), false, "write id failed, len: %{public}u", len);
    }

    uint32_t uriCount = static_cast<uint32_t>(fileUris.size());
    CHECK_AND_RETURN_RET_LOG(oss.write(reinterpret_cast<const char *>(&uriCount), sizeof(uriCount)),
        false,
        "write failed, uriCount: %{public}u",
        uriCount);
    for (const auto &uri : fileUris) {
        uint32_t len = static_cast<uint32_t>(uri.size());
        CHECK_AND_RETURN_RET_LOG(
            oss.write(reinterpret_cast<const char *>(&len), sizeof(len)), false, "write failed, len: %{public}u", len);
        CHECK_AND_RETURN_RET_LOG(oss.write(uri.data(), len), false, "write uri failed, len: %{public}u", len);
    }

    std::string str = oss.str();
    size_t size = str.size();
    bool status = parcel.WriteUint32(static_cast<uint32_t>(size));
    CHECK_AND_RETURN_RET_LOG(status, false, "Write size: %{public}zu failed", size);
    return parcel.WriteRawData(reinterpret_cast<const void *>(str.data()), size);
}
}  // namespace OHOS::Media
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

#include <sstream>
#include "add_image_dto.h"
#include "media_log.h"

namespace OHOS::Media {

AddImageDto AddImageDto::Create(const AddImageReqBody &req)
{
    MEDIA_INFO_LOG("IPC::Camera addImage: %{public}s.", req.ToString().c_str());
    AddImageDto dto;
    dto.fileId = req.fileId;
    dto.photoId = req.photoId;
    dto.deferredProcType = req.deferredProcType;
    dto.photoQuality = req.photoQuality;
    dto.subType = req.subType;
    MEDIA_INFO_LOG("IPC::Camera addImage: %{public}s.", dto.ToString().c_str());
    return dto;
}

std::string AddImageDto::ToString() const
{
    std::stringstream ss;
        ss << "{"
        << "\"fileId\": \"" << std::to_string(this->fileId) << "\","
        << "\"photoId\": \"" << this->photoId << "\","
        << "\"deferredProcType\": \"" << std::to_string(this->deferredProcType) << "\","
        << "\"photoQuality\": \"" << std::to_string(this->photoQuality) << "\","
        << "\"subType\": \"" << std::to_string(this->subType)
        << "}";
    return ss.str();
}
}  // namespace OHOS::Media
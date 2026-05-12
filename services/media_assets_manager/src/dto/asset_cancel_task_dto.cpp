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

#include "asset_cancel_task_dto.h"

namespace OHOS::Media {

CancelTaskDto CancelTaskDto::Create(const CancelTaskReqBody &req)
{
    CancelTaskDto dto;
    dto.requestId = req.requestId;
    return dto;
}

std::string CancelTaskDto::ToString() const
{
    std::string str = "CancelTaskDto{requestId=" + std::to_string(requestId) + "}";
    return str;
}

}  // namespace OHOS::Media
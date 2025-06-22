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

#include "restore_dto.h"

namespace OHOS::Media {

RestoreDto RestoreDto::Create(const RestoreReqBody &req)
{
    RestoreDto dto;
    dto.albumLpath = req.albumLpath;
    dto.keyPath = req.keyPath;
    dto.bundleName = req.bundleName;
    dto.appName = req.appName;
    dto.appId = req.appId;
    dto.isDeduplication = req.isDeduplication;
    return dto;
}

}  // namespace OHOS::Media
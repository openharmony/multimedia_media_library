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

#include "submit_cache_dto.h"

namespace OHOS::Media {

SubmitCacheDto SubmitCacheDto::Create(const SubmitCacheReqBody &req)
{
    SubmitCacheDto dto;
    dto.isWriteGpsAdvanced = req.isWriteGpsAdvanced;
    dto.values = req.values;
    return dto;
}

SubmitCacheRespBody SubmitCacheDto::CreateRespBody()
{
    SubmitCacheRespBody respBody;
    respBody.fileId = this->fileId;
    respBody.outUri = this->outUri;
    return respBody;
}
}  // namespace OHOS::Media
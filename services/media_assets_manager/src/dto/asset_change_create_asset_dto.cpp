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

#include "asset_change_create_asset_dto.h"

namespace OHOS::Media {

AssetChangeCreateAssetDto AssetChangeCreateAssetDto::Create(const AssetChangeReqBody &req)
{
    AssetChangeCreateAssetDto dto;
    dto.values = req.values;
    return dto;
}

AssetChangeRspBody AssetChangeCreateAssetDto::CreateRspBody()
{
    AssetChangeRspBody rspBody;
    rspBody.fileId = this->fileId;
    rspBody.outUri = this->outUri;
    return rspBody;
}
}  // namespace OHOS::Media
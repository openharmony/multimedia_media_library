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
 
#include "album_get_selected_assets_dto.h"
 
namespace OHOS::Media {
AlbumGetSelectedAssetsDto AlbumGetSelectedAssetsDto::Create(const AlbumGetSelectedAssetsReqBody &req)
{
    AlbumGetSelectedAssetsDto dto;
    dto.predicates = req.predicates;
    dto.columns = req.columns;
    dto.albumId = req.albumId;
    dto.filter = req.filter;
    return dto;
}
}  // namespace OHOS::Media
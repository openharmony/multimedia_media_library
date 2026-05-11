/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#define MLOG_TAG "MediaAlbumChangeSetHiddenAttributeDto"
#include "album_change_set_hidden_attribute_dto.h"

namespace OHOS::Media {
using namespace std;
void AlbumChangeSetHiddenAttributeDto::FromVo(const AlbumChangeSetHiddenAttributeReqBody &reqBody)
{
    this->albumId = reqBody.albumId;
    this->fileHidden = reqBody.fileHidden;
    this->inherited = reqBody.inherited;
    this->albumType = reqBody.albumType;
    this->albumSubType = reqBody.albumSubType;
}
} // namespace OHOS::Media
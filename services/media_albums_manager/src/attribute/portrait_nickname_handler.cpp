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

#define MLOG_TAG "PortraitNickNameHandler"

#include "portrait_nickname_handler.h"

#include "medialibrary_album_operations.h"
#include "medialibrary_errno.h"
#include "media_log.h"

namespace OHOS::Media {
const AnalysisAlbumAttributeSpec &PortraitNickNameHandler::GetSpec()
{
    return ANALYSIS_ALBUM_NICK_NAME_SPEC;
}

int32_t PortraitNickNameHandler::ValidateTarget(const std::shared_ptr<PhotoAlbum> &photoAlbum)
{
    CHECK_AND_RETURN_RET_LOG(photoAlbum != nullptr, E_INVALID_VALUES, "photoAlbum is nullptr");
    CHECK_AND_RETURN_RET_LOG(IsPortraitAlbumAttributeTarget(photoAlbum), E_OPERATION_NOT_SUPPORT,
        "only portrait album can operate nickname, albumId: %{public}d", photoAlbum->GetAlbumId());
    return E_OK;
}

int32_t PortraitNickNameHandler::Execute(const std::shared_ptr<PhotoAlbum> &photoAlbum,
    const AnalysisAlbumOperation &operation)
{
    CHECK_AND_RETURN_RET_LOG(photoAlbum != nullptr, E_INVALID_VALUES, "photoAlbum is nullptr");
    CHECK_AND_RETURN_RET_LOG(operation.attr == GetSpec().attr, E_OPERATION_NOT_SUPPORT,
        "unsupported attribute for portrait nickname handler: %{public}s", operation.attr.c_str());
    return MediaLibraryAlbumOperations::OperatePortraitAlbumNickName(std::to_string(photoAlbum->GetAlbumId()),
        operation.type, operation.values);
}
} // namespace OHOS::Media

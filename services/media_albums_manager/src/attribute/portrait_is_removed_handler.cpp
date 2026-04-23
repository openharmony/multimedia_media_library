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

#define MLOG_TAG "PortraitIsRemovedHandler"

#include "portrait_is_removed_handler.h"

#include "medialibrary_album_operations.h"
#include "medialibrary_errno.h"
#include "media_log.h"

namespace OHOS::Media {
const AnalysisAlbumAttributeSpec &PortraitIsRemovedHandler::GetSpec()
{
    return ANALYSIS_ALBUM_IS_REMOVED_SPEC;
}

int32_t PortraitIsRemovedHandler::ValidateTarget(const std::shared_ptr<PhotoAlbum> &photoAlbum)
{
    CHECK_AND_RETURN_RET_LOG(photoAlbum != nullptr, E_INVALID_VALUES, "photoAlbum is nullptr");
    CHECK_AND_RETURN_RET_LOG(IsPortraitAlbumAttributeTarget(photoAlbum), E_OPERATION_NOT_SUPPORT,
        "only portrait album can operate is removed, albumId: %{public}d", photoAlbum->GetAlbumId());
    return E_OK;
}

int32_t PortraitIsRemovedHandler::Execute(const std::shared_ptr<PhotoAlbum> &photoAlbum,
    const AnalysisAlbumOperation &operation)
{
    CHECK_AND_RETURN_RET_LOG(photoAlbum != nullptr, E_INVALID_VALUES, "photoAlbum is nullptr");
    CHECK_AND_RETURN_RET_LOG(operation.attr == GetSpec().attr, E_OPERATION_NOT_SUPPORT,
        "unsupported attribute for portrait is_removed handler: %{public}s", operation.attr.c_str());
    CHECK_AND_RETURN_RET_LOG(operation.values.size() == 1, E_OPERATION_NOT_SUPPORT,
        "unsupported value for portrait is_removed handler size: %{public}d",
        static_cast<int>(operation.values.size()));
    CHECK_AND_RETURN_RET_LOG(operation.values[0] == "0" || operation.values[0] == "1", E_OPERATION_NOT_SUPPORT,
        "unsupported value for portrait is_removed handler: %{public}s", operation.values[0].c_str());
    return MediaLibraryAlbumOperations::OperatePortraitAlbumIsRemoved(std::to_string(photoAlbum->GetAlbumId()),
        operation.values[0]);
}
} // namespace OHOS::Media

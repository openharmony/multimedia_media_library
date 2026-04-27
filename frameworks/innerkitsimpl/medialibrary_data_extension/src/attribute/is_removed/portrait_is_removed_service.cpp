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

#define MLOG_TAG "PortraitIsRemovedService"

#include "portrait_is_removed_service.h"

#include <unordered_set>

#include "analysis_album_attribute_const.h"
#include "datashare_predicates.h"
#include "media_log.h"
#include "medialibrary_analysis_album_operations.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_errno.h"
#include "photo_album_column.h"

namespace OHOS::Media {
namespace {
const std::string VALUE_RECOVER = "0";
const std::string VALUE_DISMISS = "1";
}

int32_t PortraitIsRemovedService::Operate(const std::string &albumId, const std::string &value,
    const std::shared_ptr<MediaLibraryRdbStore> &rdbStore)
{
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_HAS_DB_ERROR, "rdbStore is nullptr");
    CHECK_AND_RETURN_RET_LOG(!albumId.empty() && MediaLibraryDataManagerUtils::IsNumber(albumId), E_INVALID_VALUES,
        "target album id invalid");
    CHECK_AND_RETURN_RET_LOG(value == VALUE_RECOVER || value == VALUE_DISMISS, E_OPERATION_NOT_SUPPORT,
        "unsupported value for portrait is_removed handler: %{public}s", value.c_str());

    return MediaLibraryAnalysisAlbumOperations::SetPortraitAlbumIsRemoved(albumId, value);
}
} // namespace OHOS::Media

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
#include "media_delete_file_manager_album_processor.h"

#include <string>

#include "dfx_utils.h"
#include "file_const.h"
#include "media_file_monitor_rdb_utils.h"
#include "media_log.h"

namespace OHOS::Media {
using namespace std;

bool MediaDeleteFileManagerAlbumProcessor::ProcessInner(const MediaNotifyInfo &notifyInfo)
{
    // 特殊场景：删除到回收站（与彻底删除文件夹效果一致）
    if (notifyInfo.afterPath.find(FILE_MANAGER_TRASH_PATH) == 0) {
        MediaFileMonitorRdbUtils::DeleteFileManagerDirByFileManagerPath(notifyInfo.beforePath, rdbStore_);
        MEDIA_DEBUG_LOG("Delete trashed file assets, path: %{public}s",
            DfxUtils::GetSafePath(notifyInfo.beforePath).c_str());
        return true;
    }

    // 特殊场景：从回收站恢复
    if (notifyInfo.beforePath.find(FILE_MANAGER_TRASH_PATH) == 0) {
        MEDIA_DEBUG_LOG("Recover file assets not need to delete album, path: %{public}s",
            DfxUtils::GetSafePath(notifyInfo.beforePath).c_str());
        return true;
    }

    // 普通场景：重命名、移动
    CHECK_AND_RETURN_RET_LOG(
        MediaFileMonitorRdbUtils::DeleteFileManagerAlbumByFileManagerPath(notifyInfo.beforePath, rdbStore_), false,
        "DeleteFileManagerAlbumByFileManagerPath failed");
    return true;
}
} // namespace OHOS::Media
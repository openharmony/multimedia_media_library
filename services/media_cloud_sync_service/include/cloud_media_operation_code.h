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

#ifndef OHOS_MEDIA_CLOUD_SYNC_CLOUD_OPERATION_CODE_H
#define OHOS_MEDIA_CLOUD_SYNC_CLOUD_OPERATION_CODE_H

namespace OHOS::Media::CloudSync {
enum GLOBAL_CODE {
    OPERATION_CODE_BASE = 1,
    OPERATION_PHOTO_CODE_BASE = 100,
    OPERATION_ALBUM_CODE_BASE = 200,
};

enum class CloudMediaOperationCode : uint32_t {
    CMD_UPDATE_DIRTY_FOR_CLOUD_CHECK = OPERATION_CODE_BASE,
    CMD_UPDATE_POSITION_FOR_CLOUD_CHECK,
    CMD_UPDATE_THM_STATUS_FOR_CLOUD_CHECK,
    CMD_GET_DOWNLOAD_ASSET,
    CMD_GET_DOWNLOAD_THM,
    CMD_GET_VIDEO_TO_CACHE,
    CMD_GET_FILE_POS_STAT,
    CMD_GET_CLOUD_THM_STAT,
    CMD_GET_DIRTY_TYPE_STAT,
    CMD_GET_AGING_ASSET,
    CMD_GET_ACTIVE_AGING_ASSET,
    CMD_ON_DOWNLOAD_ASSET,
    CMD_ON_DOWNLOAD_THMS,
    CMD_GET_DOWNLOAD_THM_NUM,
    CMD_UPDATE_LOCAL_FILE_DIRTY,
    CMD_GET_DOWNLOAD_THM_BY_URI,
    CMD_UPDATE_SYNC_STATUS,
};

enum class CloudMediaPhotoOperationCode : uint32_t {
    CMD_ON_FETCH_RECORDS = OPERATION_PHOTO_CODE_BASE,
    CMD_ON_DENTRY_FILE_INSERT,
    CMD_GET_CREATED_RECORDS,
    CMD_GET_META_MODIFIED_RECORDS,
    CMD_GET_FILE_MODIFIED_RECORDS,
    CMD_GET_DELETED_RECORDS,
    CMD_GET_COPY_RECORDS,
    CMD_GET_CHECK_RECORDS,
    CMD_ON_CREATE_RECORDS,
    CMD_ON_MDIRTY_RECORDS,
    CMD_ON_FDIRTY_RECORDS,
    CMD_ON_DELETE_RECORDS,
    CMD_ON_COPY_RECORDS,
    CMD_GET_RETRY_RECORDS,
    CMD_ON_START_SYNC,
    CMD_ON_COMPLETE_SYNC,
    CMD_ON_COMPLETE_PULL,
    CMD_ON_COMPLETE_PUSH,
    CMD_ON_COMPLETE_CHECK,
};

enum class CloudMediaAlbumOperationCode : uint32_t {
    CMD_ON_FETCH_RECORDS = OPERATION_ALBUM_CODE_BASE,
    CMD_ON_DENTRY_FILE_INSERT,
    CMD_GET_CREATED_RECORDS,
    CMD_GET_META_MODIFIED_RECORDS,
    CMD_GET_DELETED_RECORDS,
    CMD_GET_CHECK_RECORDS,
    CMD_ON_CREATE_RECORDS,
    CMD_ON_MDIRTY_RECORDS,
    CMD_ON_FDIRTY_RECORDS,
    CMD_ON_DELETE_RECORDS,
    CMD_ON_COPY_RECORDS,
    CMD_ON_START_SYNC,
    CMD_ON_COMPLETE_SYNC,
    CMD_ON_COMPLETE_PULL,
    CMD_ON_COMPLETE_PUSH,
    CMD_ON_COMPLETE_CHECK,
};

enum class ThumbState : int32_t {
    DOWNLOADED,
    LCD_TO_DOWNLOAD,
    THM_TO_DOWNLOAD,
    TO_DOWNLOAD,
};

static inline const int32_t DOWNLOAD_LIMIT_SIZE = 200;
}  // namespace OHOS::Media::CloudSync
#endif  // OHOS_MEDIA_CLOUD_SYNC_CLOUD_OPERATION_CODE_H
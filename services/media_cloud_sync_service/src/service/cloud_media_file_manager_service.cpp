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

#define MLOG_TAG "Media_Service"

#include "cloud_media_file_manager_service.h"

#include "media_log.h"
#include "cloud_media_sync_utils.h"
#include "medialibrary_db_const.h"
#include "media_string_utils.h"
#include "cloud_media_sync_const.h"
#include "cloud_media_file_utils.h"
#include "media_file_utils.h"

namespace OHOS::Media::CloudSync {
void CloudMediaFileManagerService::FixFileInfo(CloudMediaPullDataDto &pullData)
{
    this->fileInfoService_.FixFileInfo(pullData);
}

bool CloudMediaFileManagerService::Accept(CloudMediaPullDataDto &pullData)
{
    // 关联不到本地资产，无需移动文件
    CHECK_AND_RETURN_RET(pullData.localPhotosPoOp.has_value(), false);
    PhotosPo photoInfo = pullData.localPhotosPoOp.value();

    // 本地是纯云资产，无需移动文件
    const bool isLocal = CloudMediaSyncUtils::FileIsLocal(photoInfo.position.value_or(0));
    CHECK_AND_RETURN_RET_LOG(isLocal, false, "file is cloud, cloudId: %{public}s", pullData.cloudId.c_str());

    const int32_t deviceFileSourceType = photoInfo.fileSourceType.value_or(0);
    const int32_t cloudFileSourceType = pullData.attributesFileSourceType;
    bool isBothMedia = deviceFileSourceType == static_cast<int32_t>(FileSourceType::MEDIA);
    isBothMedia = isBothMedia && cloudFileSourceType == static_cast<int32_t>(FileSourceType::MEDIA);
    CHECK_AND_RETURN_RET_LOG(!isBothMedia, false, "both media, skip. cloudId: %{public}s", pullData.cloudId.c_str());

    // 本地文件被写占用，无需移动文件
    const std::string deviceFileStoragePath = CloudMediaSyncUtils::FindFileStoragePath(photoInfo);
    const bool isWriteOpen = CloudMediaFileUtils::LocalWriteOpen(deviceFileStoragePath);
    CHECK_AND_RETURN_RET_LOG(
        !isWriteOpen, false, "device file write open, cloudId: %{public}s", pullData.cloudId.c_str());

    // 路径相同，无需移动文件
    const std::string cloudFileStoragePath = CloudMediaSyncUtils::FindFileStoragePathWithPullData(pullData);
    const bool isNeedRelocate = deviceFileStoragePath != cloudFileStoragePath;
    CHECK_AND_RETURN_RET_LOG(
        isNeedRelocate,
        true,
        "file path no change, "
        "cloudId: %{public}s, fileSourceType: %{public}d, storagePath: %{public}s, deviceFileStoragePath: %{public}s",
        pullData.cloudId.c_str(),
        photoInfo.fileSourceType.value_or(0),
        photoInfo.storagePath.value_or("").c_str(),
        deviceFileStoragePath.c_str());

    // 媒体桶路劲已有文件，不能再进行文件移动
    const bool isMediaFile = MediaStringUtils::StartsWith(cloudFileStoragePath, CLOUD_STORAGE_PATH_PREFIX);
    const bool isTargetMediaExists = isMediaFile && MediaFileUtils::IsFileExists(cloudFileStoragePath);
    CHECK_AND_RETURN_RET_LOG(!isTargetMediaExists,
        false,
        "target media file exists, cloudFileStoragePath: %{public}s",
        cloudFileStoragePath.c_str());

    MEDIA_INFO_LOG("Relocate Accept, cloud: %{public}s", pullData.cloudId.c_str());
    return true;
}

int32_t CloudMediaFileManagerService::RelocateFile(CloudMediaPullDataDto &pullData)
{
    // 关联不到本地资产，无需移动文件
    CHECK_AND_RETURN_RET(pullData.localPhotosPoOp.has_value(), false);
    PhotosPo photoInfo = pullData.localPhotosPoOp.value();

    CHECK_AND_RETURN_RET(this->Accept(pullData), E_OK);
    // allocate file
    const std::string deviceFileStoragePath = CloudMediaSyncUtils::FindFileStoragePath(photoInfo);
    const std::string cloudFileStoragePath = CloudMediaSyncUtils::FindFileStoragePathWithPullData(pullData);

    std::string deviceTargetFileStoragePath;
    int32_t ret = CloudMediaSyncUtils::MoveFileWithConflictResolution(
        deviceFileStoragePath, cloudFileStoragePath, deviceTargetFileStoragePath);
    // 如果 deviceTargetFileStoragePath 和 cloudFileStoragePath 不一致，则需要更新 title, display_name, storage_path 等
    MEDIA_INFO_LOG(
        "Relocate file, ret: %{public}d, "
        "deviceFileStoragePath: %{public}s, cloudFileStoragePath: %{public}s, deviceTargetFileStoragePath: %{public}s",
        ret,
        deviceFileStoragePath.c_str(),
        cloudFileStoragePath.c_str(),
        deviceTargetFileStoragePath.c_str());
    return E_OK;
}
}  // namespace OHOS::Media::CloudSync
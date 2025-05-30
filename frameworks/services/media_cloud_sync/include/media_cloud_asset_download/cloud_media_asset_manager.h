/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_CLOUD_MEDIA_ASSET_MANAGER_H
#define OHOS_CLOUD_MEDIA_ASSET_MANAGER_H

#include <iostream>
#include <memory>
#include <chrono>
#include <mutex>

#include "cloud_media_asset_download_operation.h"
#include "cloud_media_asset_types.h"
#include "medialibrary_command.h"
#include "rdb_store.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))

enum class TaskDeleteState : int32_t {
    IDLE = 0,
    ACTIVE_DELETE = 1,
    BACKGROUND_DELETE = 2
};

class CloudMediaAssetManager {
public:
    EXPORT static CloudMediaAssetManager& GetInstance();
    EXPORT int32_t HandleCloudMediaAssetUpdateOperations(MediaLibraryCommand &cmd);
    EXPORT std::string HandleCloudMediaAssetGetTypeOperations(MediaLibraryCommand &cmd);
    EXPORT int32_t StartDownloadCloudAsset(const CloudMediaDownloadType &type);
    EXPORT int32_t RecoverDownloadCloudAsset(const CloudMediaTaskRecoverCause &cause);
    EXPORT int32_t PauseDownloadCloudAsset(const CloudMediaTaskPauseCause &pauseCause);
    EXPORT int32_t CancelDownloadCloudAsset();
    EXPORT int32_t ForceRetainDownloadCloudMedia();
    EXPORT std::string GetCloudMediaAssetTaskStatus();
    EXPORT bool SetIsThumbnailUpdate();
    EXPORT int32_t GetTaskStatus();
    EXPORT int32_t GetDownloadType();
    EXPORT bool SetBgDownloadPermission(const bool &flag);
    EXPORT void CheckStorageAndRecoverDownloadTask();
    EXPORT static void DeleteAllCloudMediaAssetsAsync();
    EXPORT static void StartDeleteCloudMediaAssets();
    EXPORT static void StopDeleteCloudMediaAssets();
    EXPORT int32_t CheckCloudSyncStatus();
    EXPORT void RestartForceRetainCloudAssets();

private:
    CloudMediaAssetManager() {}
    ~CloudMediaAssetManager() {}
    CloudMediaAssetManager(const CloudMediaAssetManager &manager) = delete;
    const CloudMediaAssetManager &operator=(const CloudMediaAssetManager &manager) = delete;

    EXPORT int32_t CheckDownloadTypeOfTask(const CloudMediaDownloadType &type);
    EXPORT static int32_t DeleteBatchCloudFile(const std::vector<std::string> &fileIds);
    EXPORT static int32_t ReadyDataForDelete(std::vector<std::string> &fileIds, std::vector<std::string> &paths,
        std::vector<std::string> &dateTakens);
    static void DeleteAllCloudMediaAssetsOperation(AsyncTaskData *data);
    EXPORT int32_t UpdateCloudMediaAssets();
    EXPORT int32_t DeleteEmptyCloudAlbums();
    EXPORT int32_t UpdateLocalAlbums();
    EXPORT int32_t UpdateBothLocalAndCloudAssets();
    EXPORT static std::string GetEditDataDirPath(const std::string &path);
    EXPORT static int32_t DeleteEditdata(const std::string &path);
    EXPORT bool HasDataForUpdate(std::vector<std::string> &updateFileIds);
    EXPORT int32_t UpdateCloudAssets(const std::vector<std::string> &updateFileIds);
    EXPORT void NotifyUpdateAssetsChange(const std::vector<std::string> &notifyFileIds);
    EXPORT bool HasLocalAndCloudAssets(std::vector<std::string> &updateFileIds);
    EXPORT int32_t UpdateLocalAndCloudAssets(const std::vector<std::string> &updateFileIds);
    EXPORT void SetCloudsyncStatusKey(const int32_t statusKey);
    EXPORT void TryToStartSync();
    EXPORT int32_t ClearDeletedDbData();

private:
    static std::shared_ptr<CloudMediaAssetDownloadOperation> operation_;
    static std::atomic<TaskDeleteState> doDeleteTask_;
    static std::mutex deleteMutex_;
    static std::mutex updateMutex_;
    static std::atomic<bool> isCleaning_;
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_CLOUD_MEDIA_ASSET_MANAGER_H
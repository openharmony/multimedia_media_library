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

#ifndef FRAMEWORKS_SERVICES_MEDIA_CLOUD_ENHANCEMENT_INCLUDE_ENHANCEMENT_MANAGER_H
#define FRAMEWORKS_SERVICES_MEDIA_CLOUD_ENHANCEMENT_INCLUDE_ENHANCEMENT_MANAGER_H

#include <string>
#include <unordered_map>
#include <mutex>

#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
#include "enhancement_service_adapter.h"
#include "enhancement_database_operations.h"
#endif

#include "medialibrary_type_const.h"
#include "medialibrary_command.h"
#include "result_set.h"
#include "rdb_predicates.h"
#include "rdb_store.h"
#include "rdb_utils.h"
#include "medialibrary_rdbstore.h"
#include "enhancement_thread_manager.h"
#include "cloud_enhancement_dfx_get_count.h"
#include "settings_monitor.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))

class EnhancementManager {
public:
    EXPORT static EnhancementManager& GetInstance();
    EXPORT bool Init();
    EXPORT bool InitAsync();
    EXPORT bool LoadService();
    EXPORT void CancelTasksInternal(const std::vector<std::string> &fildIds, std::vector<std::string> &photoIds,
        CloudEnhancementAvailableType type);
    EXPORT void RemoveTasksInternal(const std::vector<std::string> &fildIds, std::vector<std::string> &photoIds);
    EXPORT bool RevertEditUpdateInternal(int32_t fileId);
    EXPORT bool RecoverTrashUpdateInternal(const std::vector<std::string> &fildIds);
#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
    EXPORT int32_t HandleAddOperation(MediaLibraryCommand &cmd, const bool hasCloudWatermark, int triggerMode = 0);
    EXPORT int32_t AddServiceTask(OHOS::MediaEnhance::MediaEnhanceBundleHandle* mediaEnhanceBundle, int32_t fileId,
        const std::string &photoId, const bool hasCloudWatermark, const bool isAuto = false);
    EXPORT int32_t HandleAutoAddOperation(bool isReboot = false);
    EXPORT int32_t AddAutoServiceTask(OHOS::MediaEnhance::MediaEnhanceBundleHandle* mediaEnhanceBundle, int32_t fileId,
        const std::string &photoId);
#endif

    EXPORT int32_t HandleEnhancementUpdateOperation(MediaLibraryCommand &cmd);
    EXPORT std::shared_ptr<NativeRdb::ResultSet> HandleEnhancementQueryOperation(MediaLibraryCommand &cmd,
        const std::vector<std::string> &columns);

    EXPORT int32_t HandlePrioritizeOperation(MediaLibraryCommand &cmd);
    EXPORT std::shared_ptr<NativeRdb::ResultSet> HandleQueryOperation(MediaLibraryCommand &cmd,
        const std::vector<std::string> &columns);
    EXPORT int32_t HandleCancelOperation(MediaLibraryCommand &cmd);
    EXPORT int32_t HandleCancelAllOperation();
    EXPORT int32_t HandlePauseAllOperation();
    EXPORT int32_t HandleResumeAllOperation();
    EXPORT int32_t HandleSyncOperation();
    EXPORT std::shared_ptr<NativeRdb::ResultSet> HandleGetPairOperation(MediaLibraryCommand &cmd);
    EXPORT int32_t HandleStateChangedOperation(const bool isCameraIdle);
    EXPORT int32_t HandlePhotosAutoOptionChange(const std::string &photosAutoOption);
    EXPORT int32_t HandleNetChange(const bool isWifiConnected, const bool isCellularNetConnected);
    EXPORT void HandlePhotosWaterMarkChange(const bool shouldAddWaterMark);

#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
    std::shared_ptr<EnhancementServiceAdapter> enhancementService_;
#endif
    std::shared_ptr<EnhancementThreadManager> threadManager_;

private:
    EnhancementManager();
    ~EnhancementManager();
    EnhancementManager(const EnhancementManager &manager) = delete;
    const EnhancementManager &operator=(const EnhancementManager &manager) = delete;
#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
    void GenerateAddServicePredicates(bool isAuto, NativeRdb::RdbPredicates &servicePredicates);
    void GenerateAddAutoServicePredicates(NativeRdb::RdbPredicates &servicePredicates);
    void GenerateCancelOperationPredicates(int32_t fileId, NativeRdb::RdbPredicates &servicePredicates);
    sptr<PhotosAutoOptionObserver> photosAutoOptionObserver_ = nullptr;
    sptr<PhotosWaterMarkObserver> photosWaterMarkObserver_ = nullptr;
    bool IsAutoTaskEnabled();
    int32_t HandleCancelAllAutoOperation();
    void ResetProcessingAutoToSupport();
    bool IsAddOperationEnabled(int32_t triggerMode);
#endif
    void InitPhotosSettingsMonitor();
    bool isCameraIdle_ = true;
    std::string photosAutoOption_ = PHOTO_OPTION_CLOSE;
    bool isWifiConnected_ = false;
    bool isCellularNetConnected_ = false;
    bool shouldAddWaterMark_ = true;

    static std::mutex mutex_;
};
} // namespace Media
} // namespace OHOS
#endif  // FRAMEWORKS_SERVICES_MEDIA_CLOUD_ENHANCEMENT_INCLUDE_ENHANCEMENT_TASK_HANDLER_H
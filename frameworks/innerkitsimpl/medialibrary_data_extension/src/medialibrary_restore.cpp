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
#define MLOG_TAG "MediaLibraryRestore"

#include "medialibrary_restore.h"
#include "dfx_utils.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_tracer.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "parameter.h"
#include "post_event_utils.h"
#ifdef CLOUD_SYNC_MANAGER
#include "cloud_sync_manager.h"
#endif

namespace OHOS {
namespace Media {
namespace {
    const std::string SWITCH_STATUS_KEY = "persist.multimedia.medialibrary.rdb_switch_status";
    const std::string CLOUD_STOP_FLAG_K = "persist.kernel.medialibrarydata.stopflag";
    const std::string CLOUD_STOP_FLAG_V = "1";
    constexpr int PARAMETER_E_OK        = 0;
    constexpr int WAIT_SECONDS          = 120;
    enum HA_SWITCH_STATUS : uint32_t {
        HA_SWITCH_READY = 0,
        HA_SWITCHING = 1
    };
} // namespace

MediaLibraryRestore &MediaLibraryRestore::GetInstance()
{
    static MediaLibraryRestore instance;
    return instance;
}

void MediaLibraryRestore::SaveHAModeSwitchStatusToPara(const uint32_t &status)
{
    int ret = SetParameter(SWITCH_STATUS_KEY.c_str(), std::to_string(status).c_str());
    CHECK_AND_RETURN_LOG((ret == PARAMETER_E_OK), "MediaLibraryRestore SetParameter switch error");
}

void MediaLibraryRestore::CheckRestore(const int32_t &errCode)
{
    MEDIA_INFO_LOG("CheckRestore is called, errcode=%{public}d", errCode);
    if (errCode != NativeRdb::E_SQLITE_CORRUPT) {
        return;
    }
    MEDIA_INFO_LOG("Restore is called");
    CHECK_AND_RETURN_LOG((!isRestoring_), "RdbStore is restoring");

    std::string date = DfxUtils::GetCurrentDateMillisecond();
    VariantMap map = {{KEY_DB_CORRUPT, std::move(date)}};
    PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_CORRUPT_ERR, map);

    isRestoring_ = true;
    std::thread([&] {
        MEDIA_INFO_LOG("MediaLibraryRestore::Restore [start]");
        auto rdb = MediaLibraryDataManager::GetInstance()->rdbStore_;
        if (rdb == nullptr) {
            isRestoring_ = false;
            MEDIA_ERR_LOG("Restore rdbStore is nullptr");
            return;
        }

        int errCode = rdb->Restore("");
        MEDIA_INFO_LOG("MediaLibraryRestore::Restore [end]. errCode = %{public}d", errCode);
        isRestoring_ = false;
    }).detach();
}

#ifdef CLOUD_SYNC_MANAGER
void MediaLibraryRestore::StopCloudSync()
{
    CHECK_AND_RETURN_LOG((isBackuping_.load()), "StopCloudSync: backuping is false, return");
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryRestore::StopCloudSync");
    FileManagement::CloudSync::CloudSyncManager::GetInstance().StopSync(BUNDLE_NAME, true);
    uint32_t times = 0;
    int ret = WaitParameter(CLOUD_STOP_FLAG_K.c_str(), CLOUD_STOP_FLAG_V.c_str(), WAIT_SECONDS);
    if (ret == PARAMETER_E_OK) {
        MEDIA_INFO_LOG("StopCloudSync success end");
        return;
    }
    isBackuping_ = false;
    MEDIA_INFO_LOG("StopCloudSync timeout error, set backup false");
}

void MediaLibraryRestore::StartCloudSync()
{
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryRestore::StartCloudSync");
    int32_t ret = FileManagement::CloudSync::CloudSyncManager::GetInstance().StartSync(BUNDLE_NAME);
    if (ret != 0) {
        MEDIA_ERR_LOG("StartCloudSync fail, errcode=%{public}d", ret);
    }
}
#endif

void MediaLibraryRestore::CheckBackup()
{
    MEDIA_INFO_LOG("CheckBackup is called");
    CHECK_AND_RETURN_LOG((!isRestoring_), "CheckBackup: is restoring, return");
    CHECK_AND_RETURN_LOG((!isBackuping_.load()), "CheckBackup: is backuping, return");

    auto rdb = MediaLibraryDataManager::GetInstance()->rdbStore_;
    CHECK_AND_RETURN_LOG((rdb != nullptr), "CheckBackup: rdbStore is nullptr");
    if (!rdb->IsSlaveDiffFromMaster()) {
        MEDIA_INFO_LOG("CheckBackup: isSlaveDiffFromMaster [false], return");
        return;
    }
    MEDIA_INFO_LOG("CheckBackup: isSlaveDiffFromMaster [true]");
    DoRdbBackup();
}

void MediaLibraryRestore::ResetHAModeSwitchStatus()
{
    auto switchStatus = HA_SWITCH_READY;
    SaveHAModeSwitchStatusToPara(std::move(switchStatus));
    isBackuping_ = false;
}

void MediaLibraryRestore::DoRdbBackup()
{
    isBackuping_ = true;
    CHECK_AND_RETURN_LOG((!isWaiting_.load()), "waiting stop cloudsync");
    SaveHAModeSwitchStatusToPara(HA_SWITCHING);
    std::thread([&] {
        MEDIA_INFO_LOG("DoRdbBackup: Backup [start]");
#ifdef CLOUD_SYNC_MANAGER
        MEDIA_INFO_LOG("DoRdbBackup: Call CloudSync start [isBackuping=%{public}d]", isBackuping_.load());
        isWaiting_ = true;
        StopCloudSync();
        isWaiting_ = false;
        MEDIA_INFO_LOG("DoRdbBackup: Call CloudSync end");
        if (!isBackuping_.load()) {
            ResetHAModeSwitchStatus();
            StartCloudSync();
            MEDIA_INFO_LOG("DoRdbBackup: isbackuping fasle, return");
            return;
        }
#endif
        auto rdb = MediaLibraryDataManager::GetInstance()->rdbStore_;
        if (rdb == nullptr) {
            ResetHAModeSwitchStatus();
#ifdef CLOUD_SYNC_MANAGER
            StartCloudSync();
#endif
            MEDIA_ERR_LOG("DoRdbBackup: rdbStore is nullptr");
            return;
        }

        if (isInterrupting_.load() || !isBackuping_.load()) {
            ResetHAModeSwitchStatus();
#ifdef CLOUD_SYNC_MANAGER
            StartCloudSync();
#endif
            MEDIA_INFO_LOG("DoRdbBackup: Interrupt or isbackuping false, return");
            return;
        }
        MediaLibraryTracer tracer;
        tracer.Start("MediaLibraryRestore::DoRdbBackup Backup");
        int errCode = rdb->Backup("");
        MEDIA_INFO_LOG("DoRdbBackup: Backup [end]. errCode = %{public}d", errCode);
        ResetHAModeSwitchStatus();
#ifdef CLOUD_SYNC_MANAGER
        StartCloudSync();
#endif
    }).detach();
}

void MediaLibraryRestore::InterruptBackup()
{
    if (!isBackuping_.load()) {
        MEDIA_INFO_LOG("rdb is not backuping, no need to interrupt");
        return;
    }
    if (isWaiting_.load()) {
        isBackuping_ = false;
        MEDIA_INFO_LOG("InterruptBackup: isWaiting, return");
        return;
    }
    auto rdb = MediaLibraryDataManager::GetInstance()->rdbStore_;
    CHECK_AND_RETURN_LOG((rdb != nullptr), "[InterruptBackup] rdbStore is nullptr");
    isInterrupting_ = true;
    int errCode = rdb->InterruptBackup();
    isInterrupting_ = false;
    isBackuping_ = false;
    MEDIA_INFO_LOG("InterruptBackup [end]. errCode = %{public}d", errCode);
    if (errCode == NativeRdb::E_OK) {
        ResetHAModeSwitchStatus();
    }
}

void MediaLibraryRestore::CheckResultSet(const std::shared_ptr<NativeRdb::ResultSet> &resultSet)
{
    if (resultSet == nullptr) {
        return;
    }
    int count;
    int errCode = resultSet->GetRowCount(count);
    CheckRestore(errCode);
}

bool MediaLibraryRestore::IsRestoring() const
{
    return isRestoring_;
}

bool MediaLibraryRestore::IsBackuping() const
{
    return isBackuping_;
}

bool MediaLibraryRestore::IsWaiting() const
{
    return isWaiting_;
}
} // namespace Media
} // namespace OHOS

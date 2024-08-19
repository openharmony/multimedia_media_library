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
#include "medialibrary_data_manager.h"
#include "medialibrary_tracer.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "parameter.h"
#ifdef CLOUD_SYNC_MANAGER
#include "cloud_sync_manager.h"
#endif

namespace OHOS {
namespace Media {
namespace {
    using HAMode                        = NativeRdb::HAMode;
    const std::string PARAM_KEY         = "persist.multimedia.medialibrary.rdb_hamode";
    const std::string SWITCH_STATUS_KEY = "persist.multimedia.medialibrary.rdb_switch_status";
    const std::string CLOUD_STOP_FLAG_K = "persist.kernel.medialibrarydata.stopflag";
    const std::string CLOUD_STOP_FLAG_V = "1";
    constexpr int32_t PARAM_LEN         = 2;
    constexpr int PARAMETER_E_OK        = 0;
    constexpr int WAIT_SECONDS          = 120;
    constexpr int MAX_FILE_SIZE         = 200 * 1024 * 1024;
    enum HA_SWITCH_STATUS : uint32_t {
        HA_SWITCH_READY = 0,
        HA_SWITCHING,
        HA_SWITCH_DONE
    };
} // namespace

MediaLibraryRestore &MediaLibraryRestore::GetInstance()
{
    static MediaLibraryRestore instance;
    return instance;
}

int32_t MediaLibraryRestore::DetectHaMode(const std::string &dbPath)
{
    // parameter first priority
    // db not exits, set hamode is main_replica mode
    // db exists, set hdmode is trigger
    ReadHAModeFromPara();
    if (haMode_ == HAMode::MAIN_REPLICA) {
        return haMode_;
    }
    // parameter is not main_replica mode, set default trigger mode
    haMode_ = HAMode::MANUAL_TRIGGER;

    bool isDbExists = MediaFileUtils::IsFileExists(dbPath);
    if (isDbExists) {
        size_t size = -1;
        bool valid = MediaFileUtils::GetFileSize(dbPath, size);
        if (valid && size <= MAX_FILE_SIZE) {
            MEDIA_INFO_LOG("MediaLibraryRestore::GetHaMode file size < 200M");
            haMode_ = HAMode::MAIN_REPLICA;
            SaveHAModeToPara();
            SaveHAModeSwitchStatusToPara(HA_SWITCH_DONE);
        }
    } else {
        MEDIA_INFO_LOG("Db File [%{public}s] is not exists", dbPath.c_str());
        haMode_ = HAMode::MAIN_REPLICA;
        SaveHAModeToPara();
        SaveHAModeSwitchStatusToPara(HA_SWITCH_DONE);
    }
    MEDIA_INFO_LOG("MediaLibraryRestore::GetHaMode = [%{public}d]", haMode_);
    return haMode_;
}

void MediaLibraryRestore::SaveHAModeToPara()
{
    int ret = SetParameter(PARAM_KEY.c_str(), std::to_string(haMode_).c_str());
    CHECK_AND_RETURN_LOG((ret == PARAMETER_E_OK), "MediaLibraryRestore::GetHaMode SetParameter hamode error");
}

void MediaLibraryRestore::SaveHAModeSwitchStatusToPara(const uint32_t &status)
{
    int ret = SetParameter(SWITCH_STATUS_KEY.c_str(), std::to_string(status).c_str());
    CHECK_AND_RETURN_LOG((ret == PARAMETER_E_OK), "MediaLibraryRestore::GetHaMode SetParameter switch error");
}

void MediaLibraryRestore::ReadHAModeFromPara()
{
    haMode_ = HAMode::MANUAL_TRIGGER;
    char ha[PARAM_LEN] = {0};
    int ret = GetParameter(PARAM_KEY.c_str(), std::to_string(haMode_).c_str(), ha, PARAM_LEN);
    if (ret > PARAMETER_E_OK) {
        haMode_ = std::stoi(ha);
        MEDIA_INFO_LOG("GetParameter haMode_ = [%{public}d]", haMode_);
    }
}

void MediaLibraryRestore::CheckRestore(const int32_t &errCode)
{
    MEDIA_INFO_LOG("CheckRestore is called, errcode=%{public}d", errCode);
    if (errCode != NativeRdb::E_SQLITE_CORRUPT) {
        return;
    }
    MEDIA_INFO_LOG("Restore is called");
    CHECK_AND_RETURN_LOG((!isRestoring_), "RdbStore is restoring");
    CHECK_AND_RETURN_LOG((haMode_ == HAMode::MAIN_REPLICA), "RdbStore is not double write mode");

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
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryRestore::StopCloudSync");
    FileManagement::CloudSync::CloudSyncManager::GetInstance().StopSync(BUNDLE_NAME);
    uint32_t times = 0;
    int ret = WaitParameter(CLOUD_STOP_FLAG_K.c_str(), CLOUD_STOP_FLAG_V.c_str(), WAIT_SECONDS);
    if (ret == PARAMETER_E_OK) {
        MEDIA_INFO_LOG("StopCloudSync success end");
        return;
    }
    isBackuping_ = false;
    MEDIA_INFO_LOG("StopCloudSync error end");
}
#endif

void MediaLibraryRestore::DoRdbHAModeSwitch()
{
    MEDIA_INFO_LOG("DoRdbModeSwitch is called");
    CHECK_AND_RETURN_LOG((haMode_ == HAMode::MANUAL_TRIGGER), "RdbStore is not trigger mode [%{public}d]", haMode_);
    CHECK_AND_RETURN_LOG((!isRestoring_), "RdbStore is restoring");
    CHECK_AND_RETURN_LOG((!isBackuping_.load()), "RdbStore is backuping");

    isBackuping_ = true;
    CHECK_AND_RETURN_LOG((!isWaiting_.load()), "waiting stop cloudsync");
    SaveHAModeSwitchStatusToPara(HA_SWITCHING);
    std::thread([&] {
        MEDIA_INFO_LOG("Backup [start]");
#ifdef CLOUD_SYNC_MANAGER
        MEDIA_INFO_LOG("Call CloudSync start");
        isWaiting_ = true;
        StopCloudSync();
        isWaiting_ = false;
        MEDIA_INFO_LOG("Call CloudSync end");
        if (!isBackuping_.load()) {
            SaveHAModeSwitchStatusToPara(HA_SWITCH_READY);
            return;
        }
#endif
        auto rdb = MediaLibraryDataManager::GetInstance()->rdbStore_;
        if (rdb == nullptr) {
            SaveHAModeSwitchStatusToPara(HA_SWITCH_READY);
            isBackuping_ = false;
            MEDIA_ERR_LOG("DoRdbHAModeSwitch rdbStore is nullptr");
            return;
        }

        if (isInterrupting_.load() || !isBackuping_.load()) {
            SaveHAModeSwitchStatusToPara(HA_SWITCH_READY);
            isBackuping_ = false;
            return;
        }
        MediaLibraryTracer tracer;
        tracer.Start("MediaLibraryRestore::DoRdbHAModeSwitch Backup");
        int errCode = rdb->Backup("");
        MEDIA_INFO_LOG("Backup [end]. errCode = %{public}d", errCode);
        if (errCode != NativeRdb::E_OK) {
            SaveHAModeSwitchStatusToPara(HA_SWITCH_READY);
            isBackuping_ = false;
            return;
        }
        haMode_ = HAMode::MAIN_REPLICA;
        SaveHAModeToPara();
        SaveHAModeSwitchStatusToPara(HA_SWITCH_DONE);
        isBackuping_ = false;
    }).detach();
}

void MediaLibraryRestore::InterruptRdbHAModeSwitch()
{
    if (!isBackuping_.load()) {
        MEDIA_INFO_LOG("rdb is not backuping, no need to interrupt");
        return;
    }
    if (isWaiting_.load()) {
        isBackuping_ = false;
        MEDIA_INFO_LOG("InterruptRdbHAModeSwitch, waiting");
        return;
    }
    auto rdb = MediaLibraryDataManager::GetInstance()->rdbStore_;
    CHECK_AND_RETURN_LOG((rdb != nullptr), "[InterruptRdbHAModeSwitch] rdbStore is nullptr");
    isInterrupting_ = true;
    int errCode = rdb->InterruptBackup();
    isInterrupting_ = false;
    isBackuping_ = false;
    MEDIA_INFO_LOG("InterruptBackup [end]. errCode = %{public}d", errCode);
    if (errCode == NativeRdb::E_OK) {
        SaveHAModeSwitchStatusToPara(HA_SWITCH_READY);
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

int32_t MediaLibraryRestore::GetHaMode() const
{
    return haMode_;
}

bool MediaLibraryRestore::IsWaiting() const
{
    return isWaiting_;
}

void MediaLibraryRestore::ResetHaMode()
{
    haMode_ = HAMode::SINGLE;
    SaveHAModeToPara();
}
} // namespace Media
} // namespace OHOS

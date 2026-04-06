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

#define MLOG_TAG "Fast_Restore"

#include "fast_restore_init_operation.h"

#include "media_log.h"
#include "application_context.h"
#include "backup_database_utils.h"
#include "media_library_upgrade_manager.h"

namespace OHOS::Media {
// backup目录下的数据库升级xml
#define UPGRADE_EVENT_PATH \
    "/storage/media/local/files/.backup/restore/data/storage/el2/base/preferences/rdb_upgrade_events.xml"
#define RDB_CONFIG_PATH \
    "/storage/media/local/files/.backup/restore/data/storage/el2/base/preferences/rdb_config.xml"
constexpr int32_t ARG_COUNT = 2;
constexpr int32_t WAL_LIMIT_SIZE = 1024 * 1024 * 1024;
constexpr int32_t STAMP_PARAM = 4;
int32_t FastRestoreCallback::OnCreate(NativeRdb::RdbStore &rdb)
{
    return 0;
}

int32_t FastRestoreCallback::OnUpgrade(NativeRdb::RdbStore &rdb, int32_t oldVersion,
    int32_t newVersion)
{
    MEDIA_INFO_LOG("OnUpgrade, old:%{public}d, new:%{public}d", oldVersion, newVersion);
    UpgradeManagerConfig config(true, UPGRADE_EVENT_PATH, RDB_CONFIG_PATH, oldVersion, newVersion);
    UpgradeManager::GetInstance().Initialize(config);
    UpgradeManager::GetInstance().UpgradeSync(rdb);
    UpgradeManager::GetInstance().UpgradeAsync(rdb);
    return 0;
}

static std::string CloudSyncTriggerFunc(const std::vector<std::string> &args)
{
    return "";
}

static std::string IsCallerSelfFunc(const std::vector<std::string> &args)
{
    return "false";
}

static std::string PhotoAlbumNotifyFunc(const std::vector<std::string> &args)
{
    return "";
}

static std::string BeginGenerateHighlightThumbnail(const std::vector<std::string> &args)
{
    return "";
}

void FastRestoreInitOperation::InitRdbStore(std::shared_ptr<NativeRdb::RdbStore>& store,
    const std::string& path)
{
    auto context = AbilityRuntime::Context::GetApplicationContext();
    CHECK_AND_RETURN_LOG(context != nullptr, "Failed to get context");
    NativeRdb::RdbStoreConfig config(CONST_MEDIA_DATA_ABILITY_DB_NAME);
    config.SetPath(path);
    config.SetBundleName(CONST_BUNDLE_NAME);
    config.SetReadConSize(CONNECT_SIZE);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S3);
    config.SetHaMode(NativeRdb::HAMode::MANUAL_TRIGGER);
    config.SetAllowRebuild(true);
    config.SetWalLimitSize(WAL_LIMIT_SIZE);
    if (context->GetArea() != DEFAULT_AREA_VERSION) {
        config.SetArea(context->GetArea());
    }
    config.SetScalarFunction("cloud_sync_func", 0, CloudSyncTriggerFunc);
    config.SetScalarFunction("is_caller_self_func", 0, IsCallerSelfFunc);
    config.SetScalarFunction("photo_album_notify_func", ARG_COUNT, PhotoAlbumNotifyFunc);
    config.SetScalarFunction("begin_generate_highlight_thumbnail", STAMP_PARAM,
        BeginGenerateHighlightThumbnail);
    int32_t err;
    FastRestoreCallback cb;
    store = NativeRdb::RdbHelper::GetRdbStore(config, MEDIA_RDB_VERSION, cb, err);
}
}
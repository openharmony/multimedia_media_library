/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#define MLOG_TAG "MediaBgTask_WalCheckProcessor"

#include "wal_check_processor.h"

#include "ffrt.h"
#include "ffrt_inner.h"
#include "media_log.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"

#include <string>
#include <sys/stat.h>

namespace OHOS {
namespace Media {
std::mutex WalCheckProcessor::walCheckPointMutex_;
constexpr ssize_t RDB_CHECK_WAL_SIZE = 50 * 1024 * 1024;   /* check wal file size : 50MB */

int32_t WalCheckProcessor::Start(const std::string &taskExtra)
{
    MEDIA_INFO_LOG("Start begin");
    ffrt::submit([this]() {
        WalCheckPoint();
        RemoveTaskName(taskName_);
        ReportTaskComplete(taskName_);
    });
    return E_OK;
}

int32_t WalCheckProcessor::Stop(const std::string &taskExtra)
{
    return E_OK;
}

void WalCheckProcessor::WalCheckPoint()
{
    MEDIA_INFO_LOG("Begin WalCheckPoint.");
    std::unique_lock<std::mutex> lock(walCheckPointMutex_, std::defer_lock);
    if (!lock.try_lock()) {
        MEDIA_WARN_LOG("wal_checkpoint in progress, skip this operation");
        return;
    }

    struct stat fileStat;
    const std::string walFile = MEDIA_DB_DIR + "/rdb/media_library.db-wal";
    if (stat(walFile.c_str(), &fileStat) < 0) {
        CHECK_AND_PRINT_LOG(errno == ENOENT, "wal_checkpoint stat failed, errno: %{public}d", errno);
        return;
    }
    ssize_t size = fileStat.st_size;
    if (size < 0) {
        MEDIA_ERR_LOG("Invalid size for wal_checkpoint, size: %{public}zd", size);
        return;
    }
    if (size <= RDB_CHECK_WAL_SIZE) {
        return;
    }

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_LOG(rdbStore != nullptr, "wal_checkpoint rdbStore is nullptr!");

    auto errCode = rdbStore->ExecuteSql("PRAGMA wal_checkpoint(TRUNCATE)");
    CHECK_AND_PRINT_LOG(errCode == NativeRdb::E_OK, "wal_checkpoint ExecuteSql failed, errCode: %{public}d", errCode);
}
} // namespace Media
} // namespace OHOS

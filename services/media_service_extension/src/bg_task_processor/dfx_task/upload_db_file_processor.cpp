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

#define MLOG_TAG "MediaBgTask_UploadDbFileProcessor"

#include "upload_db_file_processor.h"

#include "ffrt.h"
#include "ffrt_inner.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_unistore_manager.h"
#include "parameter.h"
#include "parameters.h"
#include "zip_util.h"

#include <sys/stat.h>

namespace OHOS {
namespace Media {
// BetaVersion will upload the DB, and the true uploadDBFlag indicates that uploading is enabled.
const std::string KEY_HIVIEW_VERSION_TYPE = "const.logsystem.versiontype";
int64_t g_lastTime = MediaFileUtils::UTCTimeMilliSeconds();
const int32_t TWELVE_HOUR_MS = 12*60*3600;
const int32_t MAX_FILE_SIZE_MB = 10240;
const int32_t MegaByte = 1024 * 1024;
const int32_t LARGE_FILE_SIZE_MB = 200;

std::atomic<bool> uploadDBFlag(true);

int32_t UploadDbFileProcessor::Start(const std::string &taskExtra)
{
    MEDIA_INFO_LOG("Start begin");
    ffrt::submit([this]() {
        CheckHalfDayMissions();
        RemoveTaskName(taskName_);
        ReportTaskComplete(taskName_);
    });
    return E_OK;
}

int32_t UploadDbFileProcessor::Stop(const std::string &taskExtra)
{
    return E_OK;
}

bool UploadDbFileProcessor::IsBetaVersion()
{
    static const std::string versionType = system::GetParameter(KEY_HIVIEW_VERSION_TYPE, "unknown");
    static bool isBetaVersion = versionType.find("beta") != std::string::npos;
    return isBetaVersion;
}

bool UploadDbFileProcessor::IsTwelveHoursAgo()
{
    int64_t curTime = MediaFileUtils::UTCTimeMilliSeconds();
    if (curTime - g_lastTime >= TWELVE_HOUR_MS) {
        g_lastTime = curTime;
        return true;
    }
    return false;
}

void UploadDbFileProcessor::CheckHalfDayMissions()
{
    if (IsBetaVersion() && uploadDBFlag.load() && IsTwelveHoursAgo()) {
        MEDIA_INFO_LOG("Version is BetaVersion, UploadDBFile");
        UploadDBFile();
    }
}

void UploadDbFileProcessor::UploadDBFile()
{
    uploadDBFlag.store(false);
    int64_t begin = MediaFileUtils::UTCTimeMilliSeconds();
    static const std::string databaseDir = MEDIA_DB_DIR + "/rdb";
    static const std::vector<std::string> dbFileName = { "/media_library.db",
                                                         "/media_library.db-shm",
                                                         "/media_library.db-wal" };
    static const std::string destPath = "/data/storage/el2/log/logpack";
    int64_t totalFileSize = 0;
    for (auto &dbName : dbFileName) {
        std::string dbPath = databaseDir + dbName;
        struct stat statInfo {};
        if (stat(dbPath.c_str(), &statInfo) != 0) {
            continue;
        }
        totalFileSize += statInfo.st_size;
    }
    totalFileSize /= MegaByte; // Convert bytes to MB
    if (totalFileSize > MAX_FILE_SIZE_MB) {
        MEDIA_WARN_LOG("DB file over 10GB are not uploaded, totalFileSize is %{public}ld MB",
            static_cast<long>(totalFileSize));
        uploadDBFlag.store(true);
        return ;
    }
    if (!MediaFileUtils::IsFileExists(destPath) && !MediaFileUtils::CreateDirectory(destPath)) {
        MEDIA_ERR_LOG("Create dir failed, dir=%{private}s", destPath.c_str());
        uploadDBFlag.store(true);
        return ;
    }

    UploadDBFileInner(totalFileSize);
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("Handle %{public}ld MB DBFile success, cost %{public}ld ms", static_cast<long>(totalFileSize),
        static_cast<long>(end - begin));
    uploadDBFlag.store(true);
}

void UploadDbFileProcessor::UploadDBFileInner(int64_t totalFileSize)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_LOG(rdbStore != nullptr, "rdbStore is nullptr!");

    std::string tmpPath = MEDIA_DB_DIR + "/rdb/media_library_tmp.db";
    int32_t errCode = rdbStore->Backup(tmpPath);
    CHECK_AND_RETURN_LOG(errCode == 0, "rdb backup fail: %{public}d", errCode);
    std::string destDbPath = "/data/storage/el2/log/logpack/media_library.db";
    if (totalFileSize < LARGE_FILE_SIZE_MB) {
        MediaFileUtils::CopyFileUtil(tmpPath, destDbPath);
        return;
    }

    std::string destPath = "/data/storage/el2/log/logpack/media_library.db.zip";
    int64_t begin = MediaFileUtils::UTCTimeMilliSeconds();
    std::string zipFileName = tmpPath;
    if (MediaFileUtils::IsFileExists(destPath)) {
        CHECK_AND_RETURN_LOG(MediaFileUtils::DeleteFile(destPath),
            "Failed to delete destDb file, path:%{private}s", destPath.c_str());
    }
    if (MediaFileUtils::IsFileExists(destDbPath)) {
        CHECK_AND_RETURN_LOG(MediaFileUtils::DeleteFile(destDbPath),
            "Failed to delete destDb file, path:%{private}s", destDbPath.c_str());
    }
    zipFile compressZip = ZipUtil::CreateZipFile(destPath);
    CHECK_AND_RETURN_LOG(compressZip != nullptr, "open zip file failed.");

    auto errcode = ZipUtil::AddFileInZip(compressZip, zipFileName, KEEP_NONE_PARENT_PATH);
    CHECK_AND_PRINT_LOG(errcode == 0, "AddFileInZip failed, errCode = %{public}d", errcode);

    ZipUtil::CloseZipFile(compressZip);
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("Zip db file success, cost %{public}ld ms", (long)(end - begin));
}
} // namespace Media
} // namespace OHOS

/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_MEDIALIBRARY_DOWNLOAD_CLOUD_FILES_BACKGROUND_H
#define OHOS_MEDIALIBRARY_DOWNLOAD_CLOUD_FILES_BACKGROUND_H

#include "abs_shared_result_set.h"
#include "medialibrary_async_worker.h"
#include "timer.h"
#include "userfile_manager_types.h"

namespace OHOS {
namespace Media {
class DownloadCloudFilesBackground {
public:
    static void StartTimer();
    static void StopTimer();

private:
    typedef struct {
        std::vector<std::string> paths;
        MediaType mediaType;
    } DownloadFiles;

    class DownloadCloudFilesData : public AsyncTaskData {
    public:
        DownloadCloudFilesData(DownloadFiles downloadFiles) : downloadFiles_(downloadFiles){};
        ~DownloadCloudFilesData() override = default;

        DownloadFiles downloadFiles_;
    };

    static void DownloadCloudFiles();
    static bool IsStorageInsufficient();
    static std::shared_ptr<NativeRdb::ResultSet> QueryCloudFiles();
    static void ParseDownloadFiles(std::shared_ptr<NativeRdb::ResultSet> &resultSet, DownloadFiles &downloadFiles);
    static int32_t AddDownloadTask(const DownloadFiles &downloadFiles);
    static void DownloadCloudFilesExecutor(AsyncTaskData *data);
    static void StopDownloadFiles(const std::vector<std::string> &filePaths);

    static std::recursive_mutex mutex_;
    static Utils::Timer timer_;
    static uint32_t startTimerId_;
    static uint32_t stopTimerId_;
    static std::vector<std::string> curDownloadPaths_;
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_DOWNLOAD_CLOUD_FILES_BACKGROUND_H
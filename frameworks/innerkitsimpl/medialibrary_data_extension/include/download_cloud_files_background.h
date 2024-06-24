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

namespace OHOS {
namespace Media {
class DownloadCloudFilesData : public AsyncTaskData {
public:
    DownloadCloudFilesData() = default;
    ~DownloadCloudFilesData() override = default;

    std::vector<std::string> paths;
};

class DownloadCloudFilesBackground {
public:
    static void DownloadCloudFiles();

private:
    static bool IsStorageInsufficient();
    static bool IsLocalFilesExceedsThreshold();
    static std::shared_ptr<NativeRdb::ResultSet> QueryCloudFiles();
    static void FillPhotoPaths(std::shared_ptr<NativeRdb::ResultSet> &resultSet, std::vector<std::string> &photoPaths);
    static int32_t AddDownloadTask(const std::vector<std::string> &photoPaths);
    static void DownloadCloudFilesExecutor(AsyncTaskData *data);
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_DOWNLOAD_CLOUD_FILES_BACKGROUND_H
/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIALIBRARY_BACKGROUND_CLOUD_FILE_PROCESSOR_H
#define OHOS_MEDIALIBRARY_BACKGROUND_CLOUD_FILE_PROCESSOR_H

#include "abs_shared_result_set.h"
#include "medialibrary_async_worker.h"
#include "metadata.h"
#include "rdb_predicates.h"
#include "timer.h"
#include "userfile_manager_types.h"
#include "values_bucket.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
constexpr int32_t PROCESS_INTERVAL = 5 * 60 * 1000;  // 5 minute
constexpr int32_t DOWNLOAD_DURATION = 10 * 1000; // 10 seconds

typedef struct {
    bool isCloud;
    bool isVideo;
} QueryOption;

class BackgroundCloudFileProcessor {
public:
    EXPORT static void StartTimer();
    EXPORT static void StopTimer();

private:
    typedef struct {
        std::vector<std::string> paths;
        MediaType mediaType;
    } DownloadFiles;

    typedef struct {
        int32_t fileId;
        std::string path;
        int64_t size;
        int32_t width;
        int32_t height;
        std::string mimeType;
        int32_t duration;
        MediaType mediaType;
        bool isCloud;
        bool isVideo;
    } AbnormalData;

    typedef struct {
        std::vector<AbnormalData> abnormalData;
    } UpdateData;

    class DownloadCloudFilesData : public AsyncTaskData {
    public:
        DownloadCloudFilesData(DownloadFiles downloadFiles) : downloadFiles_(downloadFiles){};
        ~DownloadCloudFilesData() override = default;

        DownloadFiles downloadFiles_;
    };

    class UpdateAbnormalData : public AsyncTaskData {
    public:
        UpdateAbnormalData(UpdateData updateData) : updateData_(updateData){};
        ~UpdateAbnormalData() override = default;

        UpdateData updateData_;
    };

    static void DownloadCloudFiles();
    static bool IsStorageInsufficient();
    static std::shared_ptr<NativeRdb::ResultSet> QueryCloudFiles();
    static void ParseDownloadFiles(std::shared_ptr<NativeRdb::ResultSet> &resultSet, DownloadFiles &downloadFiles);
    static int32_t AddDownloadTask(const DownloadFiles &downloadFiles);
    static void DownloadCloudFilesExecutor(AsyncTaskData *data);
    static void StopDownloadFiles();
    static void ProcessCloudData();
    static void UpdateCloudData();
    static std::shared_ptr<NativeRdb::ResultSet> QueryUpdateData(bool isCloud, bool isVideo);
    static void SetPredicates(NativeRdb::RdbPredicates &predicates, bool isCloud, bool isVideo);
    static void ParseUpdateData(std::shared_ptr<NativeRdb::ResultSet> &resultSet, UpdateData &updateData,
        bool isCloud, bool isVideo);
    static int32_t AddUpdateDataTask(const UpdateData &updateData);
    static void UpdateCloudDataExecutor(AsyncTaskData *data);
    static void UpdateAbnormaldata(std::unique_ptr<Metadata> &metadata, const std::string &tableName);
    static void GetSizeAndMimeType(std::unique_ptr<Metadata> &metadata);
    static int32_t GetExtractMetadata(std::unique_ptr<Metadata> &metadata);
    static void StopUpdateData();
    static void UpdateCurrentOffset(bool isCloud, bool isVideo);

    static int32_t processInterval_;
    static int32_t downloadDuration_;
    static std::recursive_mutex mutex_;
    static Utils::Timer timer_;
    static uint32_t startTimerId_;
    static uint32_t stopTimerId_;
    static std::vector<std::string> curDownloadPaths_;
    static bool isUpdating_;
    static int32_t cloudUpdateOffset_;
    static int32_t localImageUpdateOffset_;
    static int32_t localVideoUpdateOffset_;
    static int32_t cloudRetryCount_;
    static bool isDownload_;
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_BACKGROUND_CLOUD_FILE_PROCESSOR_H
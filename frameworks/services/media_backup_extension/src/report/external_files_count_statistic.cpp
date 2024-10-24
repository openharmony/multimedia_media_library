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
#include "external_files_count_statistic.h"

#include "media_log.h"
#include "backup_database_utils.h"
#include "backup_const.h"
#include "media_backup_report_data_type.h"

namespace OHOS::Media {
std::vector<AlbumMediaStatisticInfo> ExternalFilesCountStatistic::Load()
{
    if (this->externalRdb_ == nullptr) {
        MEDIA_ERR_LOG("externalRdb_ is nullptr, Maybe init failed.");
        return {};
    }
    return {this->GetMediaStatInfo(), this->GetAudioStatInfo()};
}

AlbumMediaStatisticInfo ExternalFilesCountStatistic::GetMediaStatInfo()
{
    int32_t externalImageCount = this->QueryExternalImageCount();
    int32_t externalVideoCount = this->QueryExternalVideoCount();
    AlbumMediaStatisticInfo info;
    info.sceneCode = this->sceneCode_;
    info.taskId = this->taskId_;
    info.albumName = "External_Media";
    info.imageCount = externalImageCount;
    info.videoCount = externalVideoCount;
    return info;
}

AlbumMediaStatisticInfo ExternalFilesCountStatistic::GetAudioStatInfo()
{
    int32_t externalAudioCount = this->QueryExternalAudioCount();
    AlbumMediaStatisticInfo info;
    info.sceneCode = this->sceneCode_;
    info.taskId = this->taskId_;
    info.albumName = "External_Audio";
    info.totalCount = externalAudioCount;
    return info;
}

int32_t ExternalFilesCountStatistic::QueryExternalAudioCount()
{
    static string QUERY_EXTERNAL_AUDIO_COUNT = "SELECT count(1) as count FROM files WHERE media_type = 2 AND _size > 0 \
        AND _data LIKE '/storage/emulated/0/Music%'";
    return BackupDatabaseUtils::QueryInt(this->externalRdb_, QUERY_EXTERNAL_AUDIO_COUNT, CUSTOM_COUNT);
}

int32_t ExternalFilesCountStatistic::QueryExternalImageCount()
{
    static string QUERY_EXTERNAL_IMAGE_COUNT =
        "SELECT count(1) AS count FROM files WHERE  media_type = 1 AND _size > 0";
    return BackupDatabaseUtils::QueryInt(this->externalRdb_, QUERY_EXTERNAL_IMAGE_COUNT, CUSTOM_COUNT);
}

int32_t ExternalFilesCountStatistic::QueryExternalVideoCount()
{
    static string QUERY_EXTERNAL_VIDEO_COUNT =
        "SELECT count(1) AS count FROM files WHERE  media_type = 3 AND _size > 0";
    return BackupDatabaseUtils::QueryInt(this->externalRdb_, QUERY_EXTERNAL_VIDEO_COUNT, CUSTOM_COUNT);
}
}  // namespace OHOS::Media
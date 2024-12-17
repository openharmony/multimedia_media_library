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
#include "database_report.h"

#include <sstream>

#include "media_log.h"
#include "hisysevent.h"
#include "backup_database_utils.h"
#include "backup_const.h"
#include "gallery_media_count_statistic.h"
#include "external_files_count_statistic.h"
#include "photos_count_statistic.h"

namespace OHOS::Media {
static constexpr char MEDIA_LIBRARY[] = "MEDIALIBRARY";
std::vector<AlbumMediaStatisticInfo> DatabaseReport::LoadGallery(
    std::shared_ptr<NativeRdb::RdbStore> galleryRdb, bool shouldIncludeSd)
{
    return GalleryMediaCountStatistic()
        .SetGalleryRdb(galleryRdb)
        .SetSceneCode(this->sceneCode_)
        .SetTaskId(this->taskId_)
        .SetShouldIncludeSd(shouldIncludeSd)
        .Load();
}

std::vector<AlbumMediaStatisticInfo> DatabaseReport::LoadExternal(std::shared_ptr<NativeRdb::RdbStore> externalRdb)
{
    return ExternalFilesCountStatistic()
        .SetExternalRdb(externalRdb)
        .SetSceneCode(this->sceneCode_)
        .SetTaskId(this->taskId_)
        .Load();
}

std::vector<AlbumMediaStatisticInfo> DatabaseReport::LoadMedia(
    std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb, int32_t period)
{
    return PhotosCountStatistic()
        .SetMediaLibraryRdb(mediaLibraryRdb)
        .SetSceneCode(this->sceneCode_)
        .SetTaskId(this->taskId_)
        .SetPeriod(period)
        .Load();
}

std::string DatabaseReport::ToString(const AlbumMediaStatisticInfo &info)
{
    std::stringstream ss;
    ss << "{"
       << "\"sceneCode\":\"" << info.sceneCode << "\", "
       << "\"taskId\":\"" << info.taskId << "\", "
       << "\"albumName\":\"" << info.albumName << "\", "
       << "\"totalCount\":" << info.totalCount << ", "
       << "\"imageCount\":" << info.imageCount << ", "
       << "\"videoCount\":" << info.videoCount << ", "
       << "\"hiddenCount\":" << info.hiddenCount << ", "
       << "\"trashedCount\":" << info.trashedCount << ", "
       << "\"cloudCount\":" << info.cloudCount << ", "
       << "\"favoriteCount\":" << info.favoriteCount << ", "
       << "\"burstTotalCount\":" << info.burstTotalCount << ", "
       << "\"burstCoverCount\":" << info.burstCoverCount << "}";
    return ss.str();
}

int32_t DatabaseReport::Report(std::vector<AlbumMediaStatisticInfo> statisticInfos)
{
    for (const auto &info : statisticInfos) {
        MEDIA_INFO_LOG("gallery analyze result: %{public}s", this->ToString(info).c_str());
        int32_t ret = HiSysEventWrite(MEDIA_LIBRARY,
            "MEDIALIB_BACKUP_MEDIA_STAT",
            HiviewDFX::HiSysEvent::EventType::STATISTIC,
            "SCENE_CODE",
            info.sceneCode,
            "TASK_ID",
            info.taskId,
            "ALBUM_NAME",
            info.albumName,
            "TOTAL_COUNT",
            info.totalCount,
            "IMAGE_COUNT",
            info.imageCount,
            "VIDEO_COUNT",
            info.videoCount,
            "HIDDEN_COUNT",
            info.hiddenCount,
            "TRASHED_COUNT",
            info.trashedCount,
            "FAVORITE_COUNT",
            info.favoriteCount,
            "CLOUD_COUNT",
            info.cloudCount,
            "BURST_COVER_COUNT",
            info.burstCoverCount,
            "BURST_TOTAL_COUNT",
            info.burstTotalCount);
        if (ret != 0) {
            MEDIA_ERR_LOG("GalleryMediaCountStatistic error:%{public}d", ret);
        }
    }
    return 0;
}

DatabaseReport &DatabaseReport::ReportGallery(std::shared_ptr<NativeRdb::RdbStore> galleryRdb, bool shouldIncludeSd)
{
    std::vector<AlbumMediaStatisticInfo> albumMediaStatisticInfos = this->LoadGallery(galleryRdb, shouldIncludeSd);
    this->Report(albumMediaStatisticInfos);
    return *this;
}

DatabaseReport &DatabaseReport::ReportExternal(std::shared_ptr<NativeRdb::RdbStore> externalRdb)
{
    std::vector<AlbumMediaStatisticInfo> albumMediaStatisticInfos = this->LoadExternal(externalRdb);
    this->Report(albumMediaStatisticInfos);
    return *this;
}

DatabaseReport &DatabaseReport::ReportMedia(std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb, int32_t period)
{
    std::vector<AlbumMediaStatisticInfo> albumMediaStatisticInfos = this->LoadMedia(mediaLibraryRdb, period);
    this->Report(albumMediaStatisticInfos);
    return *this;
}
}  // namespace OHOS::Media
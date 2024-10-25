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
#include "gallery_report.h"

#include <sstream>

#include "media_log.h"
#include "hisysevent.h"
#include "backup_database_utils.h"
#include "backup_const.h"
#include "gallery_media_count_statistic.h"
#include "external_files_count_statistic.h"

namespace OHOS::Media {
static constexpr char MEDIA_LIBRARY[] = "MEDIALIBRARY";
std::vector<AlbumMediaStatisticInfo> GalleryReport::Load()
{
    std::vector<AlbumMediaStatisticInfo> galleryStatInfos = GalleryMediaCountStatistic()
                                                                .SetGalleryRdb(this->galleryRdb_)
                                                                .SetSceneCode(this->sceneCode_)
                                                                .SetTaskId(this->taskId_)
                                                                .SetShouldIncludeSd(this->shouldIncludeSd_)
                                                                .Load();
    std::vector<AlbumMediaStatisticInfo> externalStatInfos = ExternalFilesCountStatistic()
                                                                 .SetExternalRdb(this->externalRdb_)
                                                                 .SetSceneCode(this->sceneCode_)
                                                                 .SetTaskId(this->taskId_)
                                                                 .Load();
    galleryStatInfos.insert(galleryStatInfos.end(), externalStatInfos.begin(), externalStatInfos.end());
    return galleryStatInfos;
}

std::string GalleryReport::ToString(const AlbumMediaStatisticInfo &info)
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

int32_t GalleryReport::Report()
{
    std::vector<AlbumMediaStatisticInfo> albumMediaStatisticInfos = this->Load();
    for (const auto &info : albumMediaStatisticInfos) {
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
}  // namespace OHOS::Media
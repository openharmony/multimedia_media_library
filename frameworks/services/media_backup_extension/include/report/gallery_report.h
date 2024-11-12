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
#ifndef OHOS_MEDIA_BACKUP_GALLERY_REPORT_H
#define OHOS_MEDIA_BACKUP_GALLERY_REPORT_H

#include <string>
#include <vector>

#include "rdb_store.h"
#include "media_backup_report_data_type.h"

namespace OHOS::Media {
class GalleryReport {
public:
    GalleryReport &SetGalleryRdb(std::shared_ptr<NativeRdb::RdbStore> galleryRdb)
    {
        this->galleryRdb_ = galleryRdb;
        return *this;
    }
    GalleryReport &SetExternalRdb(std::shared_ptr<NativeRdb::RdbStore> externalRdb)
    {
        this->externalRdb_ = externalRdb;
        return *this;
    }
    GalleryReport &SetSceneCode(int32_t sceneCode)
    {
        this->sceneCode_ = sceneCode;
        return *this;
    }
    GalleryReport &SetTaskId(const std::string &taskId)
    {
        this->taskId_ = taskId;
        return *this;
    }
    GalleryReport &SetShouldIncludeSd(bool shouldIncludeSd)
    {
        this->shouldIncludeSd_ = shouldIncludeSd;
        return *this;
    }
    int32_t Report();

private:
    std::vector<AlbumMediaStatisticInfo> Load();
    std::string ToString(const AlbumMediaStatisticInfo &info);

private:
    std::shared_ptr<NativeRdb::RdbStore> galleryRdb_;
    std::shared_ptr<NativeRdb::RdbStore> externalRdb_;
    int32_t sceneCode_;
    std::string taskId_;
    bool shouldIncludeSd_;
};
}  // namespace OHOS::Media
#endif  // OHOS_MEDIA_BACKUP_GALLERY_REPORT_H
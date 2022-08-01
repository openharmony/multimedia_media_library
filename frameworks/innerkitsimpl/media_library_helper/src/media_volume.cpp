/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "media_volume.h"

#include "medialibrary_type_const.h"

using namespace std;

namespace OHOS {
namespace Media {
MediaVolume::MediaVolume()
{
    mediaVolumeMap_.insert(make_pair(MEDIA_TYPE_FILE, DEFAULT_MEDIAVOLUME));
    mediaVolumeMap_.insert(make_pair(MEDIA_TYPE_IMAGE, DEFAULT_MEDIAVOLUME));
    mediaVolumeMap_.insert(make_pair(MEDIA_TYPE_VIDEO, DEFAULT_MEDIAVOLUME));
    mediaVolumeMap_.insert(make_pair(MEDIA_TYPE_AUDIO, DEFAULT_MEDIAVOLUME));
};
MediaVolume::~MediaVolume() = default;

void MediaVolume::SetSize(const int mediaType, const int64_t size)
{
    mediaVolumeMap_[mediaType] = size;
}

int64_t MediaVolume::GetFilesSize() const
{
    return mediaVolumeMap_.at(MEDIA_TYPE_FILE);
}

int64_t MediaVolume::GetVideosSize() const
{
    return mediaVolumeMap_.at(MEDIA_TYPE_VIDEO);
}

int64_t MediaVolume::GetImagesSize() const
{
    return mediaVolumeMap_.at(MEDIA_TYPE_IMAGE);
}

int64_t MediaVolume::GetAudiosSize() const
{
    return mediaVolumeMap_.at(MEDIA_TYPE_AUDIO);
}
}  // namespace Media
}  // namespace OHOS

/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_VOLUME_ASSET_H_
#define INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_VOLUME_ASSET_H_

#include <string>
#include <unordered_map>

namespace OHOS {
namespace Media {
/**
 * @brief Data class for MediaVolume details
 *
 * @since 1.0
 * @version 1.0
 */
class MediaVolume {
public:
    MediaVolume();
    virtual ~MediaVolume();
    void SetSize(const int mediaType, const int64_t size);

    int64_t GetFilesSize() const;
    int64_t GetVideosSize() const;
    int64_t GetImagesSize() const;
    int64_t GetAudiosSize() const;

private:
    std::unordered_map<int, int64_t> mediaVolumeMap_;
};
} // namespace Media
} // namespace OHOS

#endif  // INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_VOLUME_ASSET_H_

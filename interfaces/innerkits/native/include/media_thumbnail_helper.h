/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef MEDIA_THUMBNAIL_HELPER_H
#define MEDIA_THUMBNAIL_HELPER_H

#include <securec.h>
#include "pixel_map.h"
#include "single_kvstore.h"

namespace OHOS {
namespace Media {
static const Size DEFAULT_THUMBNAIL_SIZE = {
    .width = 256,
    .height = 256
};

class MediaThumbnailHelper {
public:
    MediaThumbnailHelper();
    ~MediaThumbnailHelper() = default;
    std::unique_ptr<PixelMap> GetThumbnail(std::string key, Size &size);
    bool isThumbnailFromLcd(Size &size);
protected:
    std::shared_ptr<DistributedKv::SingleKvStore> singleKvStorePtr_ = nullptr;
    void InitKvStore();

    // utils
    bool ResizeImage(std::vector<uint8_t> &data, Size &size, std::unique_ptr<PixelMap> &pixelMap);

    // KV Store
    bool GetImage(std::string &key, std::vector<uint8_t> &image);
    bool IsImageExist(std::string &key);
};
} // namespace Media
} // namespace  OHOS
#endif  // MEDIA_THUMBNAIL_HELPER_H

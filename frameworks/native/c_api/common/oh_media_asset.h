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

#ifndef MULTIMEDIA_MEDIA_LIBRARY_NATIVE_OH_MEDIA_ASSET_H
#define MULTIMEDIA_MEDIA_LIBRARY_NATIVE_OH_MEDIA_ASSET_H

#include <refbase.h>
#include "media_asset.h"

struct OH_MediaAsset : public OHOS::RefBase {
    explicit OH_MediaAsset(const std::shared_ptr<OHOS::Media::MediaAsset> &mediaAsset)
        : mediaAsset_(mediaAsset) {}
    ~OH_MediaAsset() = default;

    std::shared_ptr<OHOS::Media::MediaAsset> mediaAsset_ = nullptr;
};

#endif // MULTIMEDIA_MEDIA_LIBRARY_NATIVE_OH_MEDIA_ASSET_H
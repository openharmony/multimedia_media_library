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

#ifndef FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_DEFAULT_THUMBNAIL_HELPER_H_
#define FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_DEFAULT_THUMBNAIL_HELPER_H_

#include "ithumbnail_helper.h"

namespace OHOS {
namespace Media {
class DefaultThumbnailHelper : public IThumbnailHelper {
public:
    DefaultThumbnailHelper() = default;
    virtual ~DefaultThumbnailHelper() override = default;
    int32_t CreateThumbnail(ThumbRdbOpt &opts, bool isSync = false) override;
    int32_t GetThumbnailPixelMap(ThumbRdbOpt &opts,
        std::shared_ptr<DataShare::ResultSetBridge> &outResultSet) override;
};
} // namespace Media
} // namespace OHOS

#endif  // FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_DEFAULT_THUMBNAIL_HELPER_H_
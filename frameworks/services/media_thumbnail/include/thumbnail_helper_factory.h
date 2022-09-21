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

#ifndef FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_HELPER_FACTORY_H_
#define FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_HELPER_FACTORY_H_

#include "ithumbnail_helper.h"

namespace OHOS {
namespace Media {
class ThumbnailHelperFactory {
public:
    ThumbnailHelperFactory() = delete;
    virtual ~ThumbnailHelperFactory() = delete;

    static std::shared_ptr<IThumbnailHelper> GetThumbnailHelper(const Size &size);
    static bool IsThumbnailFromLcd(const Size &size);
};
} // namespace Media
} // namespace OHOS

#endif  // FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_HELPER_FACTORY_H_

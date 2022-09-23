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

#include "thumbnail_helper_factory.h"

#include "default_thumbnail_helper.h"
#include "lcd_thumbnail_helper.h"
#include "thumbnail_const.h"

using namespace std;

namespace OHOS {
namespace Media {
shared_ptr<IThumbnailHelper> ThumbnailHelperFactory::GetThumbnailHelper(const Size &size)
{
    bool isFromLcd = IsThumbnailFromLcd(size);
    if (isFromLcd) {
        shared_ptr<LcdThumbnailHelper> resultHelper = make_shared<LcdThumbnailHelper>();
        return resultHelper;
    } else {
        shared_ptr<DefaultThumbnailHelper> resultHelper = make_shared<DefaultThumbnailHelper>();
        return resultHelper;
    }
}

bool ThumbnailHelperFactory::IsThumbnailFromLcd(const Size &size)
{
    return !((size.width <= DEFAULT_THUMBNAIL_SIZE) &&
            (size.height <= DEFAULT_THUMBNAIL_SIZE));
}
} // namespace Media
} // namespace OHOS
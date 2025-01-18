/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_MEDIALIBRARY_PHOTO_DAY_MONTH_YEAR_OPERATION_H
#define OHOS_MEDIALIBRARY_PHOTO_DAY_MONTH_YEAR_OPERATION_H

#include "medialibrary_rdbstore.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
class PhotoDayMonthYearOperation {
public:
    static int32_t UpdatePhotosDateAndIdx(const std::shared_ptr<MediaLibraryRdbStore> rdbStore);

    static int32_t UpdatePhotosDateIdx(const std::shared_ptr<MediaLibraryRdbStore> rdbStore);

    EXPORT static int32_t UpdatePhotosDate(NativeRdb::RdbStore &rdbStore);

private:
    static int32_t UpdatePhotosDate(const std::shared_ptr<MediaLibraryRdbStore> rdbStore);
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_PHOTO_DAY_MONTH_YEAR_OPERATION_H
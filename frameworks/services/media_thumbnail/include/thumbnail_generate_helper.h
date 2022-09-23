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

#ifndef FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_GENERATE_HELPER_H_
#define FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_GENERATE_HELPER_H_

#include "rdb_helper.h"
#include "single_kvstore.h"
#include "thumbnail_utils.h"

namespace OHOS {
namespace Media {
class ThumbnailGenerateHelper {
public:
    ThumbnailGenerateHelper() = delete;
    virtual ~ThumbnailGenerateHelper() = delete;
    static int32_t CreateThumbnailBatch(ThumbRdbOpt &opts);
    static int32_t CreateLcdBatch(ThumbRdbOpt &opts);
private:
    static int32_t GetLcdCount(ThumbRdbOpt &opts, int &outLcdCount);
    static int32_t GetNoLcdData(ThumbRdbOpt &opts, int LcdLimit, std::vector<ThumbnailRdbData> &outDatas);
    static int32_t GetNoThumbnailData(ThumbRdbOpt &opts, std::vector<ThumbnailRdbData> &outDatas);
};
} // namespace Media
} // namespace OHOS

#endif  // FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_GENERATE_HELPER_H_

/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef ANI_SRC_INCLUDE_MEDIA_LIBRARY_ANI_H
#define ANI_SRC_INCLUDE_MEDIA_LIBRARY_ANI_H

#include "medialibrary_db_const.h"
#include "userfilemgr_uri.h"
#include "datashare_helper.h"
#include "datashare_predicates.h"
#include "userfile_client.h"
#include "safe_map.h"
#include <ani.h>
#include "ani_error.h"

namespace OHOS {
namespace Media {

class ThumbnailBatchGenerateObserver : public DataShare::DataShareObserver {
    public:
        ThumbnailBatchGenerateObserver() = default;
        ~ThumbnailBatchGenerateObserver() = default;
};
    
class ThumbnailGenerateHandler {
public:
    ThumbnailGenerateHandler() = default;
    ~ThumbnailGenerateHandler() = default;
};

class MediaLibraryAni {
public:
    static void PhotoAccessStopCreateThumbnailTask([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object,
        ani_int taskId);
};

constexpr int32_t DEFAULT_PRIVATEALBUMTYPE = 3;
struct MediaLibraryAsyncContext : public AniError {
    OHOS::DataShare::DataSharePredicates predicates;
};

} // namespace Media
} // namespace OHOS

#endif  // ANI_SRC_INCLUDE_MEDIA_LIBRARY_ANI_H

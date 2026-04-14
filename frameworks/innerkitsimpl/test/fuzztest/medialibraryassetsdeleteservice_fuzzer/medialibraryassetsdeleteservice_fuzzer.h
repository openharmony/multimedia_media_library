/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef MEDIA_ASSETS_DELETE_SERVICE_FUZZER_H
#define MEDIA_ASSETS_DELETE_SERVICE_FUZZER_H

#define FUZZ_PROJECT_NAME "media_assets_delete_service_fuzzer"

#include "cloud_media_define.h"
#include "medialibrary_type_const.h"

namespace OHOS {
namespace Media {
namespace Common {
const std::vector<PhotoPositionType> PhotoPositionType_FUZZER_LISTS = {
    PhotoPositionType::LOCAL,
    PhotoPositionType::CLOUD,
    PhotoPositionType::LOCAL_AND_CLOUD,
};

const std::vector<DirtyType> DirtyType_FUZZER_LISTS = {
    DirtyType::TYPE_NEW,
    DirtyType::TYPE_FDIRTY,
    DirtyType::TYPE_MDIRTY,
};

const std::vector<BurstCoverLevelType> BurstCoverLevelType_FUZZER_LISTS = {
    BurstCoverLevelType::COVER,
    BurstCoverLevelType::MEMBER,
};

} // namespace Common
} // namespace Media
} // namespace OHOS
#endif
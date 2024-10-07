/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef NOTIFYCHANGE_FUZZER_H
#define NOTIFYCHANGE_FUZZER_H

#define FUZZ_PROJECT_NAME "medialibraryurisensitiveoperations_fuzzer"

#include "userfile_manager_types.h"

namespace OHOS {
namespace Media {
const std::vector<MediaType> MediaType_FUZZER_LISTS = {
    MediaType::MEDIA_TYPE_FILE,
    MediaType::MEDIA_TYPE_IMAGE,
    MediaType::MEDIA_TYPE_VIDEO,
    MediaType::MEDIA_TYPE_AUDIO,
    MediaType::MEDIA_TYPE_MEDIA,
    MediaType::MEDIA_TYPE_ALBUM_LIST,
    MediaType::MEDIA_TYPE_ALBUM_LIST_INFO,
    MediaType::MEDIA_TYPE_ALBUM,
    MediaType::MEDIA_TYPE_SMARTALBUM,
    MediaType::MEDIA_TYPE_DEVICE,
    MediaType::MEDIA_TYPE_REMOTEFILE,
    MediaType::MEDIA_TYPE_NOFILE,
    MediaType::MEDIA_TYPE_PHOTO,
    MediaType::MEDIA_TYPE_ALL,
    MediaType::MEDIA_TYPE_DEFAULT,
};

} // namespace Media
} // namespace OHOS
#endif

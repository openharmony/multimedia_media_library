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

#define MLOG_TAG "MediaRecoverAssetsDto"

#include "album_recover_assets_dto.h"

#include <sstream>

namespace OHOS::Media {
using namespace std;
std::string AlbumRecoverAssetsDto::ToString() const
{
    std::stringstream ss;
    ss << "{"
       << "\"uris\": \" [";
    for (size_t i = 0; i < uris.size(); i++) {
        ss << uris[i];
        if (i != uris.size() - 1) {
            ss << ", ";
        }
    }
    ss << "]"
       << "}";
    return ss.str();
}
} // namespace OHOS::Media
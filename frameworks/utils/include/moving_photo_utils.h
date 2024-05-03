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
#ifndef MOVING_PHOTO_UTILS_H
#define MOVING_PHOTO_UTILS_H

#include <string>
#include <vector>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

namespace OHOS {
namespace Media {
#define MOVING_PHOTO_URI_SPLIT ";"
#define EXPORT __attribute__ ((visibility ("default")))
class MovingPhotoUtils {
public:
    EXPORT static bool SplitMovingPhotoUri(const std::string& src, std::vector<std::string>& ret);
    EXPORT static bool IsMediaLibraryUri(const std::string& uri);
    EXPORT static int32_t OpenReadOnlyFile(const std::string& uri, bool isReadImage);
};
} // namespace Media
} // namespace OHOS
#endif // MOVING_PHOTO_UTILS_H

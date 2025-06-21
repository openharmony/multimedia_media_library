/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef MEDIALIBRARY_DATA_ABILITY_UTILS
#define MEDIALIBRARY_DATA_ABILITY_UTILS

#include <string>
#include <vector>

#include "userfile_manager_types.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
class MediaLibraryDataManagerUtils {
public:
    EXPORT MediaLibraryDataManagerUtils();
    EXPORT ~MediaLibraryDataManagerUtils();

    EXPORT static bool IsNumber(const std::string &str);
    EXPORT static std::string GetFileIdFromPhotoUri(const std::string &uri);
    EXPORT static std::string GetOperationType(const std::string &uri);
    EXPORT static std::string GetDisPlayNameFromPath(const std::string &path);
    EXPORT static std::string ObtionCondition(std::string &strQueryCondition,
        const std::vector<std::string> &whereArgs);
    EXPORT static std::string GetTypeUriByUri(std::string &uri);
    EXPORT static int32_t GetFileIdNumFromPhotoUri(const std::string &uri);
};
} // namespace Media
} // namespace OHOS
#endif // MEDIALIBRARY_DATA_ABILITY_UTILS

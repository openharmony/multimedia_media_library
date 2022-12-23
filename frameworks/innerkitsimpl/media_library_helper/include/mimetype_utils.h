/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#ifndef OHOS_MEDIALIBRARY_MIMETYPE_UTILS_H
#define OHOS_MEDIALIBRARY_MIMETYPE_UTILS_H

#include <unordered_map>

#include "nlohmann/json.hpp"
#include "userfile_manager_types.h"

namespace OHOS {
namespace Media {
class MimeTypeUtils {
public:
    MimeTypeUtils(const MimeTypeUtils&) = delete;
    MimeTypeUtils(MimeTypeUtils&&) = delete;
    MimeTypeUtils& operator=(const MimeTypeUtils&) = delete;
    MimeTypeUtils& operator=(MimeTypeUtils&&) = delete;
    static int32_t InitMimeTypeMap();
    static std::string GetMimeTypeFromExtension(const std::string &extension);
    static MediaType GetMediaTypeFromMimeType(const std::string &mimeType);

private:
    static void CreateMapFromJson();

    static std::unordered_map<std::string, std::vector<std::string>> mediaJsonMap_;
};
}
}
#endif //OHOS_MEDIALIBRARY_MIMETYPE_UTILS_H

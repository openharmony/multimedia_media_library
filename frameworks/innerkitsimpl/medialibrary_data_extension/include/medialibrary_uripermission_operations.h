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

#ifndef OHOS_MEDIALIBRARY_BUNDLEPERMM_OPERATIONS_H
#define OHOS_MEDIALIBRARY_BUNDLEPERMM_OPERATIONS_H

#include "medialibrary_command.h"

namespace OHOS {
namespace Media {
class UriPermissionOperations {
public:
    static int32_t GetUriPermissionMode(const std::string &fileId, const std::string &bundleName, std::string &mode);
    static int32_t CheckUriPermission(const std::string &fileUri, std::string mode);
    static int32_t HandleUriPermOperations(MediaLibraryCommand &cmd);
    static int32_t HandleUriPermInsert(MediaLibraryCommand &cmd);
};

} // Media
} // OHOS
#endif // OHOS_MEDIALIBRARY_BUNDLEPERMM_OPERATIONS_H
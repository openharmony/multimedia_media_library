/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNERKITS_PERSIST_PERMISSION_COLUMN_H
#define INTERFACES_INNERKITS_PERSIST_PERMISSION_COLUMN_H

#include <string>

namespace OHOS::Media {
#define EXPORT __attribute__ ((visibility ("default")))

class PersistPermissionColumn {
public:
    static const std::string ID EXPORT;
    static const std::string PERSIST_TOKENID EXPORT;
    static const std::string PERSIST_APPIDENTIFIER EXPORT;
    static const std::string PERSIST_BUNDLE_NAME EXPORT;
    static const std::string PERSIST_BUNDLE_INDEX EXPORT;

    static const std::string PERSIST_PERMISSION_TABLE EXPORT;
    static const std::string CREATE_PERSIST_PERMISSION_TABLE EXPORT;
};

} // namespace OHOS::Media
#endif // INTERFACES_INNERKITS_PERSIST_PERMISSION_COLUMN_H
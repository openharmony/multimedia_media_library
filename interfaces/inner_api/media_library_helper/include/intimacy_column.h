/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef INTERFACE_INNERKIT_NATIVE_INCLUDE_INTIMACY_COLUMN_H
#define INTERFACE_INNERKIT_NATIVE_INCLUDE_INTIMACY_COLUMN_H

#include <string>
#include "userfilemgr_uri.h"

namespace OHOS {
namespace Media {

// table name
const std::string INTIMACY_INFO_TABLE = "tab_intimacy_info";

// tab_intimacy_info column
const std::string INTIMACY_DATA = "intimacy";
const std::string INTIMACY_IMPORTANCE = "importance";

} // namespace Media
} // namespace OHOS

#endif // INTERFACE_INNERKIT_NATIVE_INCLUDE_INTIMACY_COLUMN_H
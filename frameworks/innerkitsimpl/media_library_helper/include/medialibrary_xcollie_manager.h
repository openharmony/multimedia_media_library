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

#ifndef FRAMEWORK_INNERKITSIMPL_MEDIALIBRARY_XCOLLIE_MANAGER_H
#define FRAMEWORK_INNERKITSIMPL_MEDIALIBRARY_XCOLLIE_MANAGER_H

#include <functional>
#include <string>

namespace OHOS::Media {
static constexpr int32_t XCOLLIE_WAIT_TIME_1S = 1;
static constexpr int32_t XCOLLIE_WAIT_TIME_5S = 5;
static constexpr int32_t XCOLLIE_WAIT_TIME_60S = 60;

#define MEDIALIBRARY_XCOLLIE_MANAGER(n) MediaLibraryXCollieManager(__func__, (n), true)

class MediaLibraryXCollieManager {
public:
    MediaLibraryXCollieManager(const std::string &name, uint32_t timeout, bool recovery = true);
    ~MediaLibraryXCollieManager();
    void Cancel();
private:
    MediaLibraryXCollieManager() = default;
    int32_t xcollieId = 0;
    bool isCancel = false;
    int32_t SetXCollieTimer(const std::string &name, uint32_t timeout, bool recovery = true);
    void CancelXCollieTimer(int32_t id);
};
}

#endif
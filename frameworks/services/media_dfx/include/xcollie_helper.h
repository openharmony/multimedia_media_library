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

#ifndef OHOS_MEDIA_DFX_XCOLLIE_HELPER_H
#define OHOS_MEDIA_DFX_XCOLLIE_HELPER_H

#include <string>

namespace OHOS::Media {
#define EXPORT __attribute__ ((visibility ("default")))
class XCollieHelper {
public:
    EXPORT XCollieHelper(const std::string &name, uint32_t timeout, std::function<void(void *)> func, void *arg,
        bool recovery);
    EXPORT ~XCollieHelper();
private:
    int xcollieId_{0};
};
} // namespace OHOS::Media

#endif // OHOS_MEDIA_DFX_XCOLLIE_HELPER_H